## Sample for StackOverflow
https://stackoverflow.com/questions/68916846/how-to-use-windows-authentication-on-asp-net-core-subpath-only/68990701?noredirect=1#comment127499985_68990701

### Info
This is meant to be a sample, ripped from a project with far more code.  
The relevant bits to AD NTLM negotiation without MVC as a dependency are present here.  
We:
1. use a Middleware to detect a particular url path request, such as /auth.  
2. Initiate a Kerberos/NTLM request back to the browser, which if the browser is configured properly (IE settings) will send up the user info
3. We use that user info to talk to AD over LDAP or the Local Principal if hosted on Windows, to verify the user and pull their information/groups.
4. Custom:
   - Then respond with a hashed token/ticket indicating successful AD authorization.
   - Then client-side websocket can resolve the ticket into an auth token using the original Microsoft.Identity token. (this was done specifically because Middleware DI doesn't play well with EntityFramework DbContext).
   - You could simply subvert this on step 3 above since the user was already vetted by AD by way of browser negotiation. 


The flow I utilize here is basically this:
 - HTTP request to /auth
   - NTLM Negotiate response occurs
 - Browser handles the negotiate request using either Kerberos or NTLM, sending back to the same /auth endpoint over HTTP the user details from windows
   - "Phase 2" begins where we use LDAP or Local Principal to talk to AD, verifying the user.
 - From there it's up to you how to handle the auth. I send back a ticket and handle it using a websocket connection instead of HTTP. 


Hope this helps. I probably cannot provide any help on this. And cannot provide any warranty, use at own risk. It likely has many flaws and needs improvement. But this code was tested and worked fine.  
The Novell impl doesn't work though, as I did not need a Linux variant at this time so it's just kinda there ... half baked. LocalPrincipal and LDAPDS both work.  
All relevant sources for code copied from the web was denoted in comments with best effort.  