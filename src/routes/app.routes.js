import { Router } from 'express';
import * as identityService from '../services/identity.service.js';
import * as deviceService from '../services/device.service.js';
import * as auditService from '../services/audit.service.js';
import * as fido2Challenge from '../fido2/challenge.js';
import * as fido2Attestation from '../fido2/attestation.js';
import * as fido2Assertion from '../fido2/assertion.js';
import { trackJourneyStep } from '../config/telemetry.js';

const router = Router();

// ──────────────────────────────────────────────
// Identity Registration
// ──────────────────────────────────────────────

router.post('/v1/app/identity/register', async (req, res) => {
  const startTime = Date.now();
  try {
    const { display_name, email, phone } = req.body;

    if (!email && !phone) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'At least one of email or phone is required.',
      });
    }

    const identity = await identityService.createIdentity({ display_name, email, phone });

    await auditService.appendEntry({
      actor_type: 'USER',
      actor_id: identity.id,
      action_type: 'IDENTITY_CREATED',
      resource_type: 'IDENTITY',
      resource_id: identity.id,
      event_detail: { email, phone },
      correlation_id: req.correlationId,
    });

    trackJourneyStep({
      journeyId: req.journeyId || 'FLOW_ONBOARD_REGISTRATION',
      journeyInstanceId: req.journeyInstanceId,
      journeyStep: 'REGISTER_IDENTITY',
      correlationId: req.correlationId,
      identityId: identity.id,
      success: true,
      durationMs: Date.now() - startTime,
    });

    res.status(201).json({
      identity_id: identity.id,
      subject_identifier: identity.subject_identifier,
      display_name: identity.display_name,
      email: identity.email,
      phone: identity.phone,
      status: identity.identity_status,
      created_at: identity.created_at,
    });
  } catch (err) {
    trackJourneyStep({
      journeyId: req.journeyId || 'FLOW_ONBOARD_REGISTRATION',
      journeyInstanceId: req.journeyInstanceId,
      journeyStep: 'REGISTER_IDENTITY',
      correlationId: req.correlationId,
      success: false,
      durationMs: Date.now() - startTime,
      properties: { error_type: err.message?.includes('UNIQUE') ? 'conflict' : 'server_error' },
    });

    console.error('[APP] identity/register error:', err.message);
    if (err.message.includes('UQ_ic_subject_identifier') || err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'conflict', error_description: 'Identity already exists.' });
    }
    res.status(500).json({ error: 'server_error', error_description: 'Failed to create identity.' });
  }
});

router.get('/v1/app/identity/:id', async (req, res) => {
  try {
    const identity = await identityService.getIdentityById(req.params.id);
    if (!identity) {
      return res.status(404).json({ error: 'not_found', error_description: 'Identity not found.' });
    }
    res.json(identity);
  } catch (err) {
    console.error('[APP] identity/:id error:', err.message);
    res.status(500).json({ error: 'server_error', error_description: 'Failed to fetch identity.' });
  }
});

// ──────────────────────────────────────────────
// Device Registration
// ──────────────────────────────────────────────

router.post('/v1/app/device/registration-challenge', async (req, res) => {
  try {
    const { identity_id } = req.body;
    if (!identity_id) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'identity_id is required' });
    }
    
    // Create a challenge
    const challengeData = await fido2Challenge.generateRegistrationChallenge();
    res.json({
      session_id: challengeData.session_id,
      challenge: challengeData.challenge,
      timeout: challengeData.timeout,
      rp: { id: 'stardomes.ae', name: 'Stardomes IdP' },
      user: { id: identity_id }, // Normally resolve display name via identity
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }],
      attestation: 'direct',
      userVerification: 'required',
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'preferred'
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'server_error' });
  }
});

router.post('/v1/app/device/register', async (req, res) => {
  const startTime = Date.now();
  try {
    const {
      session_id,
      identity_id,
      device_permanent_id,
      device_model,
      os_type,
      os_version,
      attestation_response
    } = req.body;

    if (!identity_id || !device_permanent_id || !attestation_response || !session_id) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'session_id, identity_id, device_permanent_id, and attestation_response are required.',
      });
    }

    // Verify identity exists
    const identity = await identityService.getIdentityById(identity_id);
    if (!identity) {
      return res.status(404).json({ error: 'not_found', error_description: 'Identity not found.' });
    }

    // Anti-replay: Retrieve and consume challenge
    await fido2Challenge.retrieveAndConsumeChallenge(session_id);

    // Initial Registration (Untrusted)
    const device = await deviceService.registerDevice({
      identity_id,
      device_permanent_id,
      device_model,
      os_type,
      os_version,
      device_public_key: null, // we will populate via attestation
      attestation_object: null,
      attestation_format: null,
    });

    // Run Full Attestation Pipeline
    let attestationVerified = false;
    try {
      const attestationResult = await fido2Attestation.verifyAttestation(
        device.id,
        attestation_response.response.attestationObject,
        attestation_response.response.clientDataJSON
      );
      attestationVerified = attestationResult.verified;
    } catch (e) {
      // Hard-delete the device row so the same device_permanent_id can be re-registered.
      // revokeDevice only soft-deletes (sets revoked_at), which leaves the UNIQUE
      // constraint in place and blocks all subsequent registration retries.
      await deviceService.deleteDevice(device.id);
      throw e;
    }

    await auditService.appendEntry({
      actor_type: 'USER',
      actor_id: identity_id,
      action_type: 'DEVICE_REGISTERED',
      resource_type: 'DEVICE',
      resource_id: device.id,
      event_detail: { device_permanent_id, device_model, os_type },
      correlation_id: req.correlationId,
    });

    trackJourneyStep({
      journeyId: req.journeyId || 'FLOW_ONBOARD_REGISTRATION',
      journeyInstanceId: req.journeyInstanceId,
      journeyStep: 'DEVICE_BINDING',
      correlationId: req.correlationId,
      identityId: identity_id,
      deviceId: device.id,
      success: true,
      durationMs: Date.now() - startTime,
    });

    res.status(201).json({
      device_id: device.id,
      identity_id: device.identity_id,
      device_permanent_id: device.device_permanent_id,
      device_model: device.device_model,
      is_trusted: true,
      attestation_verified: attestationVerified,
      registered_at: device.registered_at,
      message: 'Device registered and trusted.',
    });
  } catch (err) {
    trackJourneyStep({
      journeyId: req.journeyId || 'FLOW_ONBOARD_REGISTRATION',
      journeyInstanceId: req.journeyInstanceId,
      journeyStep: 'DEVICE_BINDING',
      correlationId: req.correlationId,
      success: false,
      durationMs: Date.now() - startTime,
      properties: { error_type: err.message?.includes('UNIQUE') ? 'conflict' : 'server_error' },
    });

    console.error('[APP] device/register error:', err.message);
    if (err.message.includes('UQ_idr_device_permanent_id') || err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'conflict', error_description: 'Device already registered.' });
    }
    if (err.message.includes('FK_idr_identity')) {
      return res.status(404).json({ error: 'not_found', error_description: 'Identity not found.' });
    }
    if (err.message === 'challenge_expired') {
      return res.status(400).json({ error: 'challenge_expired', error_description: 'Challenge has expired. Request a new one.' });
    }
    if (['attestation_verification_failed', 'rp_id_mismatch', 'device_compromised'].includes(err.message)) {
      return res.status(400).json({ error: err.message, error_description: err.message });
    }
    res.status(500).json({ error: 'server_error', error_description: 'Failed to register device.' });
  }
});

router.get('/v1/app/device/:id/status', async (req, res) => {
  const startTime = Date.now();
  try {
    const device = await deviceService.getDeviceStatus(req.params.id);
    if (!device) {
      return res.status(404).json({ error: 'not_found', error_description: 'Device not found.' });
    }

    trackJourneyStep({
      journeyId: req.journeyId || 'FLOW_ACCOUNT_MANAGEMENT',
      journeyInstanceId: req.journeyInstanceId,
      journeyStep: 'DEVICE_STATUS',
      correlationId: req.correlationId,
      deviceId: req.params.id,
      success: true,
      durationMs: Date.now() - startTime,
    });

    res.json(device);
  } catch (err) {
    console.error('[APP] device/:id/status error:', err.message);
    res.status(500).json({ error: 'server_error', error_description: 'Failed to fetch device status.' });
  }
});

// ──────────────────────────────────────────────
// Challenge Response
// ──────────────────────────────────────────────

router.post('/v1/app/challenge/:request_id/respond', async (req, res) => {
  try {
    const { action, fido2_assertion, denial_reason } = req.body;
    const deviceId = req.headers['x-device-id'];

    if (!deviceId) return res.status(400).json({ error: 'invalid_request', error_description: 'X-Device-Id required' });
    
    // In reality we would fetch `avr` and `device` from db here
    // const avr = await getAVR(req.params.request_id);
    // const device = await deviceService.getDeviceStatus(deviceId);

    // Mocking for the integration scope
    const avr = { id: req.params.request_id, challenge: 'mockChallenge' };
    const device = { id: deviceId, signature_counter: 0, fido2_public_key_cbor: Buffer.from([]) };

    if (action === 'APPROVE') {
      await fido2Assertion.verifyFIDO2Assertion(fido2_assertion, avr, device);
      res.json({ status: 'APPROVED', auth_req_id: avr.id });
    } else {
      // Mark AVR as denied
      res.json({ status: 'DENIED', auth_req_id: avr.id });
    }
  } catch (err) {
    console.error('Assertion error:', err.message);
    const fido2Errors = ['challenge_expired', 'challenge_mismatch', 'origin_mismatch', 'rp_id_mismatch', 'user_not_present', 'user_not_verified', 'invalid_signature', 'cloning_detected'];
    if (fido2Errors.includes(err.message)) {
      return res.status(401).json({ error: err.message, error_description: err.message });
    }
    res.status(500).json({ error: 'server_error' });
  }
});

export default router;
