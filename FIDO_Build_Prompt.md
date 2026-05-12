The IDP Backend has been already built e.g. API contracts in the Build_Plan.md and the AUTH_TOKEN_SETUP.md ,
database tables that storge the user identity, and currently how the session is handled by the bankend. 

Currently the function points 
B-SB-01  
B-SB-02  
B-SB-03  
B-SB-04
leverage the Azure Service Bus to relay the request to the satellite terminal ,
the response will be a Device 2fa authentication response after the user biometric verification like faceid / touchid etc.

1. Identity Creation
   1.1 How do we create the digital identity for the user
   a) What are the cryptographic utilties , methodolgies , what is the output and where is it stored ?
   b) What are the inputs used ( birth data , birth cert number , national identity number , mothers maiden name , parts of name , checksum of the name) ?
   c) how are they first verified with other database like national identity API etc, passport , driving license etc
   d) How is the digital identity referenced , it needs a cleartext identfier that usualy be a user account number (alpha numberic or numeric or uuid)

2. 2FA Creation/Binding/Enroll ( Device side)
   2.1) How do we Enroll/register the user second factor as 2FA security binding.
   a) User FaceID and TouchID ( has a digital signature )
   b) Verified with national database for faceid/fingerprint
   c) Binding process and refernce id for the binding

3. 2FA ( Enrollment in the backend )
   3.1 How does the IDP backend store the 2fa enrollment and store the binding

4. 3rd party 2FA authenication request
   4.1 Request/Response API structure for 3rd party requestor
   4.2 How do we really know the request is coming for a specified user ( not mis represented , spoofed etc)
   4.3 How does the bankend now remeber the session and the user authentication request
   4.3 How do we ensure that the user1 request will be send to only the user1 phone app for challenge/response
   4.4 What is the security process in place for the mobile app notification push for authentication is for the correct user?
   4.4 What is the response structure from the phone app for the 2fa challange ( what happens if the 2fa failed?)
   4.5 if the 2fa challenge is responsed successfully , how does the mobile app respond ?
   4.6 What is the response structure ?

5. Response Method , simultaneous request/response or batch ?
   5.1 What is the reponse type , Is it writen to a response service bus queue ?  
   5.2 How do we ensure the response is sent to the correct session ?
   5.3 Since the reponse come from serveral devices to the same response queue , does it tranform a online multi threaded request/response model to a batch processing model?
   5.4 what is the expected methology to reach the reponse to the correct request thread, something like a hook model ?.

6. Response Processing of 2FA
   6.1 How do we validate the response is valid and it is indeed for the challenge we send
   6.2 Does the response have some uinque token (bread crumbs) we sent earlier that is returned back and to add to the faith the same token is send back transformed by a secret key that only the intended reciever possess )
   6.3 How do we validat agaist replay attack , man in the middle attack , or other attacks etc.
