## Anope API

Each endpoint takes form encoded data and returns a JSON response.

Each endpoint requires an API key from Snoonet Staff to access.

Every endpoint accepts an optional `user_ip` parameter to specify the IP address of the user the action is being done on behalf of. Some endpoints require this parameter.

### Generic Errors

`{"error":{"id":"missing_parameters","message":"Missing required request parameters","parameters":[<MISSING_PARAMS>]},"status":"error"}` - Occurs when a required parameter is not supplied for this request

### `/api/register` - Register an account
#### Params (required unless specified otherwise)
- `username` - Username of the account to register
- `password` - Password to register the accouht with
- `email` _optional if forceemail=false in anope_ - The email address to associate with this account
- `source` -  A string identifying where the user is registering from, for `m_store_server`
- `user_ip` - The IP address of the user creating this account

#### Responses
##### Success

`{"session":"<SESSION_ID>","status":"ok","verify":"<VERIFY_TYPE>","need_confirm": true|false}`
- `VERIFY_TYPE` may be `mail`, `admin`, or `none`. This indicates the account verification method that is configured.

##### Errors
    _Note: The `message` field is meant only to describe the error to a user, this text may change unexpectedly_


`{"error":{"id":"name_in_use","message":"This username is in use by another user and can not be registered"},"status":"error"}`

`{"error":{"id":"user_exists","message":"A user with that name is already registered"},"status":"error"}`

`{"error":{"id":"no_guest","message":"Guest nicknames may not be registered"},"status":"error"}`

`{"error":{"id":"invalid_name","message":"Username is invalid"},"status":"error"}`

`{"error":{"id":"missing_email","message":"An email address is required for registration"},"status":"error"}`

`{"error":{"id":"invalid_email","message":"A valid email address is required for registration"},"status":"error"}`

`{"error":{"id":"invalid_password","message":"That password is invalid"},"status":"error"}`

### `/api/confirm` - Confirm an account registration
#### Params (required unless otherwise specified)
- `session` - The `session` ID returned from the `/api/register` call
- `code` - The user's verification code for their account
- `user_ip` - The IP address of the user confirming this account

#### Responses
##### Success

`{"status":"ok"}`

##### Errors

`{"error":{"id":"no_login","message":"You are not logged in to an account"},"status":"error"}`

`{"error":{"id":"already_confirmed","message":"This account is already confirmed"},"status":"error"}`

`{"error":{"id":"wrong_code","message":"Incorrect confirmation code supplied"},"status":"error"}`

### `/api/login` - Begin a session for a user
#### Params (required unless otherwise specified)
- `username` - The user's username
- `password` - The user's password
- `user_ip` - The IP address of the user logging in

#### Responses
##### Success

`{"session":"<SESSION_ID>","account":"<ACCOUNT_NAME>","status":"ok","unconfirmed":true|false}`

##### Errors

`{"error":{"id":"failed_login","message":"Invalid login credentials"},"status":"error"}`

### `/api/logout` - Terminate a session
#### Params
- `session` - The session to terminate

#### Responses
##### Success

`{"status":"ok"}`

#### Errors

`{"error":{"id":"no_login","message":"You are not logged in to an account"},"status":"error"}`

