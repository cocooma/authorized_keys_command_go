# authorized_keys_command_go

It returns the `active` ssh public key/s from the AWS Key store as long as they exit.
The public keys do not need to be deployed any more to the boxes.


### Install instructions
Add the following lines to the `/etc/ssh/sshd_config`
```
   AuthorizedKeysCommand /usr/local/bin/authorized_keys_command_go
   AuthorizedKeysCommandUser nobody
```
Install the deb. package.

### Prerequisites 

- Create an aws iam policy and corresponding role which allows public key retrieval.
- Tag the aws ec2 instance/s with the follwing tag name: `auth-account-arn`.<BR/> 
  The tag value has to be the name of the above iam role.  

  
### Build the deb package
