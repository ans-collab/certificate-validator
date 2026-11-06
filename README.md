# Certificate Validator

## What is Certificate Validator?
An API for validating a certificate sent by a server. It checks that the following are valid: 
1) validity date
2) signature  
3) chain
4) hostname - compares hostname to the certificate's SAN


## URL

```
https://
```
 


## Tech Spec
- Spring Framework, SpringBoot
- CI/CD via Github Actions publishes to AWS (EC2)
- JUnit Testing
- note: https://*.badssl.com is used for testing

## Author
Christine Chavez
<br>
https://www.linkedin.com/in/christinechavez/
