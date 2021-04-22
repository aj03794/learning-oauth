# Learning OAuth

- Course: https://www.udemy.com/course/oauth-2-simplified

## History of OAuth

- Applications typically used HTTP basic auth
    - Just sends username and password to API
    - For example, twitter would ask for your gmail password so that it could work with gmail
- OAuth was driven for the need for having 3rd party apps connect to platforms
- OAuth 1 required using api keys in a way that wasn't safe for mobile phones

## How OAuth Improves Application Security

- As a user, if an application asks for your password - you don't really know what it is doing with it
- From the APIs perspective, if you take a password from a client side app, how do you know that it's actually that person making the request?
    - An attacker may take a password dump from some other service and just start trying passwords
- OAuth requires that every application send out usrs to the oauth server and then redirects users back to the application
    - Users leave application and go to the oauth service to type in their password. They never give their password to the application
- Reduces number of places users enter passwords
    - Also gives much more flexibility for adding something like MFA later

## OAuth vs OpenID Connect

- Often used together but are different things
- Different security considerations

### OAuth

- OAuth was originally designed for applications to get access to APIs
    - The application doesn't need to actually know who the user is that is using the application
- OAuth is like checking into a hotel
    - You give hotel ID and payment and they give you hotel key
    - Hotel key gives you access to rooms in hotel
    - A door doesn't know who you are, the person at the front desk knows who you are
    - The key represents access to resources
- Front desk employee is the oauth server
    - They check ID and authenticate the user
- Keycards are access tokens
- The door to the rooms are resources (`resource servers`)
- OAuth was created as a delegated authorization protocol
    - It has been extended to be used as a SSO protocol through things like OpenID Connect

<br>

### OpenID Connect

- If the application does need to know who the user is - like show their name in the UI or show their profile picture - that is where you need something besides OAuth - this is done using `OpenID Connect`
- OpenID Connect is built on top of OAuth
    - OAuth server can communicate info about the user back to the user
- It does

<br>

- OAuth issues access tokens to apps
- OpenID connect issues ID tokens to apps
- **OAuth is about accessing APIs**
- **OpenID Connect is about identifying users**

## Roles in OAuth

- Typical scenario of a user trying to access some data in an API, we have 4 roles
- User (resource owner)
    - Person with the account
- Device (user agent)
    - User is using the device
        - Phone, web browser, etc
- Application (oauth client)
    - App is running on the device that the user is using
- API (resource server)
    - App is making requests to API
- New Role - authorization server
    - Manage access to the API that it's protecting
    - User logs in at authorization server and application gets access token in response
    - API then needs to be able to validate the access token

<br>

- These roles don't necessarily have to be individual components
- The authorization server and resource server can be deployed on a single server and be apart of the same code base
- In other architectures, may have a distinct authorization server and a bunch of microservices that make up the resource server
    - Maybe you have an API gateway out in front of your microservices

## Application Types

- OAuth 2.0 defines two client types
    - Confidential and Public clients
- Difference between these two are whether they can be deployed with some sort of credentials that can be used in the authentication process
- Confidential clients have the ability to be deployed with a client secret where that secret won't be visible to anyone using the app
    - This is common for backend apps that run on some sort of server
    - Application can use its credentials to authenticate the requests that it makes
    - This means that the oauth server will know that only the real application can make requests if it includes the applications credentials
- Public clients can't be deployed with application secrets
    - If you're writing a mobile app or SPA then you can't include secrets in the app because users of the app could see the secret
    - For example, users of a web app for look at the app's source code in the browser
    - You can't ship a secret in that application and expect it to remain secret
    - This isn't as obvious in a mobile app but there are plenty of tools to exact strings out of binary files that make up the app
    - This also includes things like an Apple TV or an IoT device
    - `Authorization server can't really ever be sure that requests being made from public clients are genuine or are being made by a bad actor`

<br>

- Authorization server might have different policies based on the application type
- For example, a confidential client might have the consent screen skipped because the auth server can verify the client because of the credentials passed by the confidential client

<br>

- Two pieces to this
    - Can a client authenticate the requests it makes
    - Does the authorization server the client's identity

<br>

- New application type in OAuth 2.1 called a `credentialed` client
    - Has credentials but has not had it's identity confirmed by the authorization server
    - Example of this is mobile app that launches for the first time
        - Mobile app uses dynamic client registration to get a client secret
        - First request can't contain any authentication because there is no way to deploy app with authentication
        - In future requests, mobile app uses same token going forward

## User Consent

![](./images/1.png)

- This type of screen is known as the `consent screen`
    - Asking user for permission
- User gives username and password to client library that makes POST request to auth server to get an access token
- User only ever types in their password into the authorization server
    - This guarantees to the authorization server that the user is sitting there right now using the application
    - If authorization server just accepted the username and password of a user, the authorization server doesn't know whether the user is actually sitting there or if an application is making a request with stored credentials and the user isn't there at all
- Authorization server displays to the user what type of access they're consenting to
    - This is the consent step in the screenshot above
- This redirect to the authoriztaion server allows easy integration with MFA
    - Then every application uses that authorization server would use MFA
- Asking for consent is typically skipped for first party confidential clients
    - Usually user is automatically redirected back

## Front Channel vs Back Channel

- How data moves between systems
- Back channel is the normal/secure way
    - Client to server connection over https
    - Client knows what server we're talking to because we can validate that certificate
    - Once the client is established, the data is encrypted in transit so that we know nobody can modify it
    - You can trust the response from the server because you know where it came from
    - Like hand delivering a package
    - Back channel doesn't mean a server side application, it means a client to server application
        - Still get certificate verification and an encrypted connection
    - So you're client facing javascript app can still have a back channel
- Front channel is using the address bar of the user's browser to move data between two systems
    - Like a delivery system vs hand delivering
    - No direct link between sender and recipient
    - It is used to insert the client between the application and the authorization server
    - Thay way the authorization server knows that the user is actually present and has given their permission
    - OAuth describes sending access token back in redirect which is security issue - this is called `implicit flow`
        - Uses front channel for both the requests the app makes as well as delivering the access token
        - Bad but browsers had no other choice - no cross origin resource sharing (CORS)
        - The solution is to send the access token through the back channel and this was made possible when browsers built in support for CORS
    
## Application Identity

- Application building up a URL to redirect user to authorization server
    - URL will contain scope of the request
    - The redirect URI telling the authorization server where to send the user back to
    - client id to tell which app is making the request
- App then redirects the user's browser there which takes them to authorization server
- User logs in at the authorizatio server
- Approves the request the app makes
- Authorization server needs to redirect them back to the app
- Authorization server sends short tty `authorization code` in the redirect back to client application that the application can use to make a request to get the access token
    - What if this authorization code gets stolen?
    - That's what the client secret is for
    - Application sends client secret and authorization code to authorization server to get access token once the redirect is complete
    - What if an app can't prove it's identity? This would be the case for apps with public clients (SPAs, mobile apps, etc)
        - Public clients uses PKCE (proof key for code exchange)
        - Public clients make a secret at the beginning of the authorization flow and use it until the end of the flow - this is the subsitution for the client id
            - This doesn't prove the app's identity
            - Just makes sure that the authroization code is used by the same app that starts it
- Redirect URI is the location of the client where the authorizaton user sends the user back to after they log in
    - This is where the authorization code will be delivered in the front channel
- `No perfect solution for public clients`

## OAuth clients

- OAuth client is the application that's going to be getting and using an access token to make API requests

## OAuth for Server-Side Applications

### Registering an Application

- Step one is registering application at oauth server
- You go to developer website of the service you're writing an app for, register as a developer, and then go create applicatios
    - This works for services that have public APIs like google, twitter, facebook, etc
- Registering gives you credentials that you can use with the oauth flow
- Requires a few pieces of information and in turn you'll get back a `client id` and optionally you may get a `client secret`
    - Usually you see a place to enter name of the api and one or more places to redirect URIs
    - Some may ask for description, logo of the app, links to terms of service for the app
- Server may ask you what type of app you're building
- This redirect URI ensures that users can't be redirected back to an attackers app instead of your own
    - You can't include wildcards because that's a vector that an attacker could use - `redirect attacks`
- `client id` is okay to put in the source code, that's public information
    - It's used to identify your app throughout the oauth flow
- `client secret` is the application's password and that is how the app will authenticate with the token endpoint to get access tokens
    - end user applications can't protect a client secret
- For a server side app you can deploy the secret in an env variable, config file, config server, etc

### Authorization Code Flow for Web Applications

- User wants to use the applicaiton
- App (on the server) generates a new secret and hashes it
    - This is not the client secret. This secret is different everytime it starts an authorization flow. This is called the `PKCE Code verifier`
    - App then creates a hash of the `PKCE Code verifier` which is called the `PKCE Code Challenge`. Hash is a one way operation.
- App builds URL to send browser to authorization server. It sends the hash with this request
- User ends up at oauth server delivering the message the app sent
    - This is the first message sent in the front channel
    - Browser is using address bar to send messages between two other computers
        - Computer one is the app on the server
        - Computer two is the oauth server
- OAuth server asks user to login
- OAuth server asks if they really are trying to log into the app
- OAuth server redirects user back to browser with a one time authorization code
    - Takes app's redirect URI, adds the authorization code in the query string and then sends the user's browser there to allow the user to deliver it back to the app
    - Second message sent in the front channel
    - Authorization code is only good for 1 use and it has to be redeemed within a short period of time - usually under a minute
- Once the app has the authorization code, it can go through the back channel and make a request to the oauth server to get an access code
    - This request includes authorization code, application's client ID, plaintext client secret, and plaintext PKCE secret
- OAuth server verifies client ID and client secret. It also takes `PKCE secret` and calculates a hash of it to make sure the hash matches the `code challenge` that was sent at the beginning of the flow
    - OAuth server generates access token and returns it in the response
- Flow is complete, app can go make API requests with the access token

<br>

- Doing these steps with PKCE prevents what's called the `authorization code injection` where an attacker could end up logged in as a real user in the application
- PKCE is recommended for all application types

<br>

- `Code verifier` (secret) is a random string thats 43-128 characters long
- `Code challenge` (public hash) is `base64url(sha256(code_verifier))`
- Url looks something like this
    - https://authorization-server/auth?
        response_type=code
        &client_id=CLIENT_ID
        &redirect_uri=REDIRECT_URI
        &scope=photos
        &state=XXXXXXX
        &code_challenge=XXXXXXXXXX
        &code_challenge_method=S256
        - response_type=code tells oauth server that you're doing the authorization code flow
        - redirect_uri has to match one of the redirect URIs you added when registering the app
        - `state` allows you to store application specific state. This is only safe to use if the oauth server supports PKCE. If it DOESN'T, this has to be a random string
            - This can be like which page to redirect the user to after they log in
- If it works, user will be redirected back to URL that looks like this
    - https://example-app.com/redirect?
        code=AUTH_CODE_HERE
        &state=XXXXXX
    - If there was an error for some reason, you'd have `error=access_denied` instead of `code=AUTH_CODE_HERE`
- Should check that the state you sent matches the state you got back (CSRF protection)
- Now you can use that authorization code to make a back channel https request from application server to oauth server's token endpoint
    - POST https://authorization-server.com/token
    - Body will be a form-encoded body
    - Parameters in request will be
    ```
    grant_type=authorization_code&
    code=AUTH_CODE_HERE&
    redirect_uri=REDIRECT_URI&
    code_verifier=VERIFIER_STRING&
    client_id=CLIENT_ID&
    client_secret=CLIENT_SECRET
    ```
- If everything works, authorization server will get a reply like the one below

![](./images/2.png)

- When you need to refresh the token, you make another post request

```
grant_type=refresh_token&
refresh_token=REFRESH_TOKEN&
client_id=CLIENT_ID&
client_secret=CLIENT_SECRET
```

- If this is successful, you'll get back a response like the screenshot above
- Lots of legitimate reasons that the refresh token may not work
    - User could be deleted
    - User could have revoked the permissions
    - Admin may have locked the account
    - App has to start new auth flow from the beginning

<br>

- If a server doesn't support PKCE, you can still code your client to use it for the future. The server will ignore the PKCE parameters

### JWT Access Tokens

- Most common way to implement self encoded tokens
- base 64 encoded data in 3 parts
    - There's a dot to notate the separate sections
- First 2 parts are base64 encoded JSON and the last one is the signature
- Base64 decoding these parts and you'll get plain json
- It can also be encrypted but it is more common for oauth servers to just sign them
- Once a JWT is created, it can neber be changed
- JWTs can be encryted and signed, but they do not have to be either encrypted or signed

![](./images/3.png)

- First part is called the header
- Describes signing algorithm and possibly which key was used to sign it

<br>

- Middle part is the payload

<br>

- When using JTWs for access tokens, there are a couple of reserved `claims`
- `iss` - issuer, identifier of the server that issued token
- `exp` - expiration - unix timestamp
- `iat` - issued at
- `aud` - audience, identity of the intended party that's going to be reading and validating the JTW token
    - This is resource server
- `sub` - short for subject
    - Identifier for who the token represents. If there is a user involved, this identifies them
    - If no user involved then it will be client id of the application
- `client_id`
- `jti` - json webtoken id
    - Unique ientifier for this particular token which a resource server can use to see if a token is being used more than once
- optional params
    - `scope`
    - `auth_time` - last time user authenticated with authorization server
        - API can use this to determine if a user needs to be reauthenticated
    - `acr` and `acm`
        - From OpenID Connect
        - `acr` is the authenticatin context class reference
            - If the access token was issued when the user was already logged in at the server, instead of confirming their password, this would be 0 and it shouldn't be allowed to do an operations that have monetary value like purchasing
        - `amr` is authentication methods reference
            - How the user authenticated as a list of strings - like `pwd` for password
- Authorization server can add additional properties to these

### Remote Token Introspection

- Only your APIs should validate access tokens
- App should send access token to API and let API decide whether it is valid or not
- How can an API check that an access token is valid?
    - Ask authorization server if it is valid
    - Slow because it's a network request
    - If random string then this is your only option
    - For JWT then you might be able to validate it yourself in the API
- Token introspection endpoint
- Make a POST request `/introspection` and include the token in the form of the body `token=XYZ`
    - API also has to pass something that proves it has access to do this
    - Sometimes may reuse the client id and secret
    - Get JSON object with at least the property `active` and it will be `true` or `false`
    - OAuth servers may do this piece differently
- For a high traffic API, you may not want to go to the oauth server to check validity upon every request

### Local Token Validation

- "The fast way" - no network traffic
- API validates the token and doesn't use the oauth server
- OAuth server probably provides own libraries for you to do this

### API Gateway

- Sits in front of backend apps
- All requests from internet comes through the api gateway
- Handles requests with valid tokens but also expired tokens
- Only does local validation
- Can quickly reject obviously bad requests
- Will pass through valid tokens as well as revoked tokens
    - API gateway has no way to know that revoked tokens should be rejected because tokens haven't expired. It would have to go to auth server to see if token was valid
- Now up to each application to device if the fast validation that the gateway did was good enough
    - For nonsensitive API methods, it can't leak sensitive data so maybe it's okay to respond to these revoked tokens
    - This makes a lot of sense with access tokens that have short time to live (like an hour) - the API knows that the token was good an hour ago
    - For sensitive APIs, they should go to the authorization server and see if the token is actually good or not
- Gateway handles bulk of validation and it only lets through valid or revoked tokens
- APIs only make few introspection requests
- This works if you have some sort of middleware in your API