## Anope API

Each endpoint takes form encoded data and returns a JSON response.

Each endpoint requires an API key from Snoonet Staff to access.

Every endpoint accepts an optional `user_ip` parameter to specify the IP address of the user the action is being done on behalf of. Some endpoints require this parameter.

### Generic Errors

`{"error":{"id":"missing_parameters","message":"Missing required request parameters","parameters":[<MISSING_PARAMS>]},"status":"error"}` - Occurs when a required parameter is not supplied for this request

### `/register` - Register an account
#### Params (required unless specified otherwise)
- `username` - Username of the account to register
- `password` - Password to register the accouht with
- `email` _optional if forceemail=false in anope_ - The email address to associate with this account
- `source` -  A string identifying where the user is registering from, for `m_store_server`
- `user_ip` - The IP address of the user creating this account
- `ident` _optional_ - If specified, is used to populate the default access list for the new account
- `oauth` _optional_ - If set to `1`, requires that the API wrapper verify the email address against the IRC.com API. This parameter only applies to the IRC.com implementation of this API.

#### Responses
##### Success

`{"session":"<SESSION_ID>","status":"ok","verify":"<VERIFY_TYPE>","need_verify": true|false}`
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

### `/confirm` - Confirm an account registration
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

### `/login` - Begin a session for a user
#### Params (required unless otherwise specified)
- `username` - The user's username
- `password` - The user's password
- `user_ip` - The IP address of the user logging in

#### Responses
##### Success

`{"session":"<SESSION_ID>","account":"<ACCOUNT_NAME>","status":"ok","verified":true|false}`

##### Errors

`{"error":{"id":"failed_login","message":"Invalid login credentials"},"status":"error"}`

### `/logout` - Terminate a session
#### Params
- `session` - The session to terminate

#### Responses
##### Success

`{"status":"ok"}`

#### Errors

`{"error":{"id":"no_login","message":"You are not logged in to an account"},"status":"error"}`

### `/resetpass` - Reset a password for a user
#### Params
- `account`
- `email`

#### Responses
##### Success

`{"status":"ok"}` - Returned if the password reset email was sent or the account/email don't match a valid account, meaning it will "silently" (logged internally) ignore invalid account details

#### Errors

`{"error":{"id":"mail_failed","message":"Unable to send reset email"},"status":"error"}`

### `/resetpass/confirm` - Confirm a password reset
#### Params
- `account` - Account name to reset the password for
- `code` - Confirmation code from the user
- `newpass` - Sets the new password

#### Responses
##### Success

`{"status":"ok"}`

##### Errors

`{"error":{"id":"wrong_code","message":"Invalid reset token"},"status":"error"}`

`{"error":{"id":"expired_code","message":"Expired reset token"},"status":"error"}`

`{"error":{"id":"invalid_password","message":"That password is invalid"},"status":"error"}`

### `/user/set/password` - Set the user's password
#### Params
- `session`
- `newpass`

#### Responses
##### Success

`{"status":"ok"}`

##### Errors

`{"error":{"id":"no_login","message":"You are not logged in to an account"},"status":"error"}`

`{"error":{"id":"invalid_password","message":"That password is invalid"},"status":"error"}`

### `/user/token/add` - Add an authentication token to the user's account

Authentication tokens can be used in place of passwords anywhere a password is needed

#### Params
- `session`
- `name`

#### Responses
##### Success

`{"status":"ok","token":{"token":"<AUTH_TOKEN>","name":"<TOKEN_NAME>"}}`

##### Errors

`{"error":{"id":"token_add_failed","message":"Unable to add token"},"status":"error"}`

`{"error":{"id":"tokens_disabled","message":"Token authentication appears to be disabled"},"status":"error"}`

### `/user/token/list` - List current authentication tokens on the account
#### Params
- `session`

#### Responses
##### Success

`{"status":"ok","tokens":[{"token":"<AUTH_TOKEN>","name":"<TOKEN_NAME>","id":1}]}`

##### Errors

`{"error":{"id":"tokens_disabled","message":"Token authentication appears to be disabled"},"status":"error"}`

### `/user/token/delete` - Remove an authentication token
#### Params
- `id` - Either the numeric ID or the token itself to be removed

#### Responses
##### Success

`{"status":"ok"}`

##### Errors

`{"error":{"id":"tokens_disabled","message":"Token authentication appears to be disabled"},"status":"error"}`

`{"error":{"id":"no_token","message":"No matching token found."},"status":"error"}`

### `/user/tags/add` - Associates a message tag with a user's account

Authentication tags can be used in place of passwords anywhere a password is needed

#### Params
- `session`
- `name` -  Tag name.
- `value` - Tag value.

#### Responses
##### Success

`{"session":"<AUTH_TOKEN>","status":"ok"}`

##### Errors

`{"error":{"id":"no_login","message":"Login required"},"status":"error"}`

{"error":{"id":"invalid_tag_key","message":"Tag key contains an invalid character."},"status":"error"}

### `/user/tags/delete` - Disassociates a message tag from a user's account
#### Params
- `session`
- `name` -  Tag name.

#### Responses
##### Success

`{"session":"<AUTH_TOKEN>","status":"ok"}`

##### Errors

`{"error":{"id":"no_login","message":"Login required"},"status":"error"}`

`{"error":{"id":"no_tag","message":"No matching tag found."},"status":"error"}`

### `/user/tags/list` - Lists message tags associated with a user's account
#### Params
- `session`

#### Responses
##### Success

`{"session":"<AUTH_TOKEN>","status":"ok","tags":{"tagname":"tag value"}}`

##### Errors

`{"error":{"id":"no_login","message":"Login required"},"status":"error"}`

