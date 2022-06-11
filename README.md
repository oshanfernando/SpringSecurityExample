

Spring Boot Security (Oauth2) Example
============================

The code demonstrates the use Spring Boot and Spring Security to create a simple application that implements 
security features such as:

* Login / Register
* JWT Bearer token authorization
* Use of Refresh token
* Oauth2 / OIDC integration with Google
* Role based authorization
* Method level security using @PreAuthorize annotation
* Using a custom login form (override spring default)


Requirements
------------
* Java 11
* Spring boot version 2.7.0
* Maven 3.8+

Quick start
-----------
1. Create Oauth2 client ID and a secret from  [Google API Console](https://console.developers.google.com/). Provide http://localhost:8081/login/oauth2/code/google for Authorized redirect URIs. 
2. Set client ID and secret in the application.properties
<pre>spring.security.oauth2.client.registration.google.client-id=
spring.security.oauth2.client.registration.google.client-secret=
</pre>
3. run `mvn clean spring-boot:run`
4. Point your browser to [http://localhost:8081/register](http://localhost:8081/register) to directly create an account.
5. Visit [http://localhost:8081/login](http://localhost:8081/login) to login from the above credentials or use Google Login.


REST API endpoints
-------------

| Endpoint               | Description                                         | Secured |
|------------------------|:----------------------------------------------------|--------:|
| app/register           | Create new user                                     |  public |
| app/login              | Login using username/password                       |  public |
| app/refreshtoken       | Get new JWT token from refresh token                |  public |
| /app/secure/user       | Secured endpoint for Both USER/ADMIN roles          | secured |
| /app/secure/admin      | Secured endpoint for Both ADMIN role                | secured |



