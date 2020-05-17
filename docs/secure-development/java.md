# Introduction

Scan use Find-sec-bugs and PMD for analyzing Java source code. Below are the list of rules along with code snippets showing best practices.

## Predictable pseudorandom number generator[<small></small>](#PREDICTABLE_RANDOM "Permanent link")

_<small>Bug Pattern: <tt>PREDICTABLE_RANDOM</tt></small>_

The use of a predictable random value can lead to vulnerabilities when used in certain security critical contexts. For example, when the value is used as:

- a CSRF token: a predictable token can lead to a CSRF attack as an attacker will know the value of the token
- a password reset token (sent by email): a predictable password token can lead to an account takeover, since an attacker will guess the URL of the "change password" form
- any other secret value

A quick fix could be to replace the use of `java.util.Random` with something stronger, such as `java.security.SecureRandom`.

**Vulnerable Code:**

    String generateSecretToken() {
        Random r = new Random();
        return Long.toHexString(r.nextLong());
    }

**Solution:**

    import org.apache.commons.codec.binary.Hex;

    String generateSecretToken() {
        SecureRandom secRandom = new SecureRandom();

        byte[] result = new byte[32];
        secRandom.nextBytes(result);
        return Hex.encodeHexString(result);
    }

### References
- [Cracking Random Number Generators - Part 1 (https://jazzy.id.au)](https://jazzy.id.au/2010/09/20/cracking_random_number_generators_part_1.html)
- [CERT: MSC02-J. Generate strong random numbers](https://www.securecoding.cert.org/confluence/display/java/MSC02-J.+Generate+strong+random+numbers)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [Predicting Struts CSRF Token - Example of real-life vulnerability and exploitation](https://blog.h3xstream.com/2014/12/predicting-struts-csrf-token-cve-2014.html)


## Predictable pseudorandom number generator (Scala)[<small></small>](#PREDICTABLE_RANDOM_SCALA "Permanent link")

_<small>Bug Pattern: <tt>PREDICTABLE_RANDOM_SCALA</tt></small>_

The use of a predictable random value can lead to vulnerabilities when used in certain security critical contexts. For example, when the value is used as:

- a CSRF token: a predictable token can lead to a CSRF attack as an attacker will know the value of the token
- a password reset token (sent by email): a predictable password token can lead to an account takeover, since an attacker will guess the URL of the "change password" form
- any other secret value

A quick fix could be to replace the use of `java.util.Random` with something stronger, such as **java.security.SecureRandom**.

**Vulnerable Code:**

    import scala.util.Random

    def generateSecretToken() {
        val result = Seq.fill(16)(Random.nextInt)
        return result.map("%02x" format _).mkString
    }

**Solution:**

    import java.security.SecureRandom

    def generateSecretToken() {
        val rand = new SecureRandom()
        val value = Array.ofDim[Byte](16)
        rand.nextBytes(value)
        return value.map("%02x" format _).mkString
    }

### References
- [Cracking Random Number Generators - Part 1 (http://jazzy.id.au)](https://jazzy.id.au/2010/09/20/cracking_random_number_generators_part_1.html)
- [CERT: MSC02-J. Generate strong random numbers](https://www.securecoding.cert.org/confluence/display/java/MSC02-J.+Generate+strong+random+numbers)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [Predicting Struts CSRF Token (Example of real-life vulnerability and exploitation)](https://blog.h3xstream.com/2014/12/predicting-struts-csrf-token-cve-2014.html)
-
## Untrusted servlet parameter[<small></small>](#SERVLET_PARAMETER "Permanent link")

_<small>Bug Pattern: <tt>SERVLET_PARAMETER</tt></small>_

The Servlet can read GET and POST parameters from various methods. The value obtained should be considered unsafe. You may need to validate or sanitize those values before passing them to sensitive APIs such as:

- SQL query (May leads to SQL injection)
- File opening (May leads to path traversal)
- Command execution (Potential Command injection)
- HTML construction (Potential XSS)
- etc...

### References
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

## Untrusted Content-Type header[<small></small>](#SERVLET_CONTENT_TYPE "Permanent link")

_<small>Bug Pattern: <tt>SERVLET_CONTENT_TYPE</tt></small>_

The HTTP header Content-Type can be controlled by the client. As such, its value should not be used in any security critical decisions.

### References
[CWE-807: Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

## Untrusted Hostname header[<small></small>](#SERVLET_SERVER_NAME "Permanent link")

_<small>Bug Pattern: <tt>SERVLET_SERVER_NAME</tt></small>_

The hostname header can be controlled by the client. As such, its value should not be used in any security critical decisions. Both `ServletRequest.getServerName()` and `HttpServletRequest.getHeader("Host")` have the same behavior which is to extract the `Host` header.

    GET /testpage HTTP/1.1
    Host: www.example.com
    [...]

The web container serving your application may redirect requests to your application by default. This would allow a malicious user to place any value in the Host header. It is recommended that you do not trust this value in any security decisions you make with respect to a request.

### References
- [CWE-807: Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

## Untrusted session cookie value[<small></small>](#SERVLET_SESSION_ID "Permanent link")

_<small>Bug Pattern: <tt>SERVLET_SESSION_ID</tt></small>_

The method [`HttpServletRequest.getRequestedSessionId()`](<http://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#getRequestedSessionId()>) typically returns the value of the cookie `JSESSIONID`. This value is normally only accessed by the session management logic and not normal developer code.

The value passed to the client is generally an alphanumeric value (e.g., `JSESSIONID=jp6q31lq2myn`). However, the value can be altered by the client. The following HTTP request illustrates the potential modification.

    GET /somePage HTTP/1.1
    Host: yourwebsite.com
    User-Agent: Mozilla/5.0
    Cookie: JSESSIONID=Any value of the user's choice!!??'''">

As such, the JSESSIONID should only be used to see if its value matches an existing session ID. If it does not, the user should be considered an unauthenticated user. In addition, the session ID value should never be logged. If it is, then the log file could contain valid active session IDs, allowing an insider to hijack any sessions whose IDs have been logged and are still active.

### References
- [OWASP: Session Management Cheat Sheet](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

## Untrusted query string[<small></small>](#SERVLET_QUERY_STRING "Permanent link")

_<small>Bug Pattern: <tt>SERVLET_QUERY_STRING</tt></small>_

The query string is the concatenation of the GET parameter names and values. Parameters other than those intended can be passed in.

For the URL request `/app/servlet.htm?a=1&b=2`, the query string extract will be `a=1&b=2`

Just as is true for individual parameter values retrieved via methods like `HttpServletRequest.getParameter()`, the value obtained from `HttpServletRequest.getQueryString()` should be considered unsafe. You may need to validate or sanitize anything pulled from the query string before passing it to sensitive APIs.

### References
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

## HTTP headers untrusted[<small></small>](#SERVLET_HEADER "Permanent link")

_<small>Bug Pattern: <tt>SERVLET_HEADER</tt></small>_

Request headers can easily be altered by the requesting user. In general, no assumption should be made that the request came from a regular browser without modification by an attacker. As such, it is recommended that you not trust this value in any security decisions you make with respect to a request.

### References
- [CWE-807: Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

## Untrusted Referer header[<small></small>](#SERVLET_HEADER_REFERER "Permanent link")

_<small>Bug Pattern: <tt>SERVLET_HEADER_REFERER</tt></small>_

Behavior:

- Any value can be assigned to this header if the request is coming from a malicious user.
- The "Referer" will not be present if the request was initiated from another origin that is secure (HTTPS).

Recommendations:

- No access control should be based on the value of this header.
- No CSRF protection should be based only on this value ([because it is optional](https://www.w3.org/Protocols/HTTP/HTRQ_Headers.html#z14)).

### References
- [CWE-807: Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

## Untrusted User-Agent header[<small></small>](#SERVLET_HEADER_USER_AGENT "Permanent link")

_<small>Bug Pattern: <tt>SERVLET_HEADER_USER_AGENT</tt></small>_

The header "User-Agent" can easily be spoofed by the client. Adopting different behaviors based on the User-Agent (for crawler UA) is not recommended.

### References
- [CWE-807: Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

## Potentially sensitive data in a cookie[<small></small>](#COOKIE_USAGE "Permanent link")

_<small>Bug Pattern: <tt>COOKIE_USAGE</tt></small>_

The information stored in a custom cookie should not be sensitive or related to the session. In most cases, sensitive data should only be stored in session and referenced by the user's session cookie. See HttpSession (`HttpServletRequest.getSession()`)

Custom cookies can be used for information that needs to live longer than and is independent of a specific session.

### References
- [CWE-315: Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)

## Potential Path Traversal (file read)[<small></small>](#PATH_TRAVERSAL_IN "Permanent link")

_<small>Bug Pattern: <tt>PATH_TRAVERSAL_IN</tt></small>_

A file is opened to read its content. The filename comes from an **input** parameter. If an unfiltered parameter is passed to this file API, files from an arbitrary filesystem location could be read.

This rule identifies **potential** path traversal vulnerabilities. In many cases, the constructed file path cannot be controlled by the user. If that is the case, the reported instance is a false positive.

**Vulnerable Code:**

    @GET
    @Path("/images/{image}")
    @Produces("images/*")
    public Response getImage(@javax.ws.rs.PathParam("image") String image) {
        File file = new File("resources/images/", image); //Weak point

        if (!file.exists()) {
            return Response.status(Status.NOT_FOUND).build();
        }

        return Response.ok().entity(new FileInputStream(file)).build();
    }

**Solution:**

    import org.apache.commons.io.FilenameUtils;

    @GET
    @Path("/images/{image}")
    @Produces("images/*")
    public Response getImage(@javax.ws.rs.PathParam("image") String image) {
        File file = new File("resources/images/", FilenameUtils.getName(image)); //Fix

        if (!file.exists()) {
            return Response.status(Status.NOT_FOUND).build();
        }

        return Response.ok().entity(new FileInputStream(file)).build();
    }

### References
- [WASC: Path Traversal](http://projects.webappsec.org/w/page/13246952/Path%20Traversal)
- [OWASP: Path Traversal](https://www.owasp.org/index.php/Path_Traversal)
- [CAPEC-126: Path Traversal](https://capec.mitre.org/data/definitions/126.html)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

## Potential Path Traversal (file write)[<small></small>](#PATH_TRAVERSAL_OUT "Permanent link")

_<small>Bug Pattern: <tt>PATH_TRAVERSAL_OUT</tt></small>_

A file is opened to write to its contents. The filename comes from an **input** parameter. If an unfiltered parameter is passed to this file API, files at an arbitrary filesystem location could be modified.

This rule identifies **potential** path traversal vulnerabilities. In many cases, the constructed file path cannot be controlled by the user. If that is the case, the reported instance is a false positive.

### References
- [WASC-33: Path Traversal](http://projects.webappsec.org/w/page/13246952/Path%20Traversal)
- [OWASP: Path Traversal](https://www.owasp.org/index.php/Path_Traversal)
- [CAPEC-126: Path Traversal](https://capec.mitre.org/data/definitions/126.html)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

## Potential Path Traversal using Scala API (file read)[<small></small>](#SCALA_PATH_TRAVERSAL_IN "Permanent link")

_<small>Bug Pattern: <tt>SCALA_PATH_TRAVERSAL_IN</tt></small>_

A file is opened to read its content. The filename comes from an **input** parameter. If an unfiltered parameter is passed to this file API, files from an arbitrary filesystem location could be read.

This rule identifies **potential** path traversal vulnerabilities. In many cases, the constructed file path cannot be controlled by the user. If that is the case, the reported instance is a false positive.

**Vulnerable Code:**

    def getWordList(value:String) = Action {
      if (!Files.exists(Paths.get("public/lists/" + value))) {
        NotFound("File not found")
      } else {
        val result = Source.fromFile("public/lists/" + value).getLines().mkString // Weak point
        Ok(result)
      }
    }

**Solution:**

    import org.apache.commons.io.FilenameUtils;

    def getWordList(value:String) = Action {
      val filename = "public/lists/" + FilenameUtils.getName(value)

      if (!Files.exists(Paths.get(filename))) {
        NotFound("File not found")
      } else {
        val result = Source.fromFile(filename).getLines().mkString // Fix
        Ok(result)
      }
    }

### References
- [WASC: Path Traversal](http://projects.webappsec.org/w/page/13246952/Path%20Traversal)
- [OWASP: Path Traversal](https://www.owasp.org/index.php/Path_Traversal)
- [CAPEC-126: Path Traversal](https://capec.mitre.org/data/definitions/126.html)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

## Potential Command Injection[<small></small>](#COMMAND_INJECTION "Permanent link")

_<small>Bug Pattern: <tt>COMMAND_INJECTION</tt></small>_

The highlighted API is used to execute a system command. If unfiltered input is passed to this API, it can lead to arbitrary command execution.

**Vulnerable Code:**

    import java.lang.Runtime;

    Runtime r = Runtime.getRuntime();
    r.exec("/bin/sh -c some_tool" + input);

### References
- [OWASP: Command Injection](https://www.owasp.org/index.php/Command_Injection)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

## Potential Command Injection (Scala)[<small></small>](#SCALA_COMMAND_INJECTION "Permanent link")

_<small>Bug Pattern: <tt>SCALA_COMMAND_INJECTION</tt></small>_

The highlighted API is used to execute a system command. If unfiltered input is passed to this API, it can lead to arbitrary command execution.

**Vulnerable Code:**

    def executeCommand(value:String) = Action {
        val result = value.!
        Ok("Result:\n"+result)
    }

### References
- [OWASP: Command Injection](https://www.owasp.org/index.php/Command_Injection)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

## FilenameUtils not filtering null bytes[<small></small>](#WEAK_FILENAMEUTILS "Permanent link")

_<small>Bug Pattern: <tt>WEAK_FILENAMEUTILS</tt></small>_

Some `FilenameUtils'` methods don't filter NULL bytes (`0x00`).

If a null byte is injected into a filename, if this filename is passed to the underlying OS, the file retrieved will be the name of the file that is specified prior to the NULL byte, since at the OS level, all strings are terminated by a null byte even though Java itself doesn't care about null bytes or treat them special. This OS behavior can be used to bypass filename validation that looks at the end of the filename (e.g., ends with `".log"`) to make sure it's a safe file to access.

To fix this, two things are recommended:

- Upgrade to Java 7 update 40 or later, or Java 8+ since [NULL byte injection in filenames is fixed in those versions](http://bugs.java.com/bugdatabase/view_bug.do?bug_id=8014846).
- Strongly validate any filenames provided by untrusted users to make sure they are valid (i.e., don't contain null, don't include path characters, etc).

If you know you are using a modern version of Java immune to NULL byte injection, you can probably disable this rule.

### References
- [WASC-28: Null Byte Injection](http://projects.webappsec.org/w/page/13246949/Null%20Byte%20Injection)
- [CWE-158: Improper Neutralization of Null Byte or NUL Character](https://cwe.mitre.org/data/definitions/158.html)

## TrustManager that accept any certificates[<small></small>](#WEAK_TRUST_MANAGER "Permanent link")

_<small>Bug Pattern: <tt>WEAK_TRUST_MANAGER</tt></small>_

Empty TrustManager implementations are often used to connect easily to a host that is not signed by a root [certificate authority](https://en.wikipedia.org/wiki/Certificate_authority). As a consequence, this is vulnerable to [Man-in-the-middle attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) since the client will trust any certificate.

A TrustManager allowing specific certificates (based on a TrustStore for example) should be built. Detailed information for a proper implementation is available at: [[1]](https://stackoverflow.com/a/6378872/89769) [[2]](https://stackoverflow.com/a/5493452/89769)

**Vulnerable Code:**

    class TrustAllManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            //Trust any client connecting (no certificate validation)
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            //Trust any remote server (no certificate validation)
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }

**Solution (TrustMangager based on a keystore):**

    KeyStore ks = //Load keystore containing the certificates trusted

    SSLContext sc = SSLContext.getInstance("TLS");

    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
    tmf.init(ks);

    sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(),null);

### References
- [WASC-04: Insufficient Transport Layer Protection](http://projects.webappsec.org/w/page/13246945/Insufficient%20Transport%20Layer%20Protection)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

## HostnameVerifier that accept any signed certificates[<small></small>](#WEAK_HOSTNAME_VERIFIER "Permanent link")

_<small>Bug Pattern: <tt>WEAK_HOSTNAME_VERIFIER</tt></small>_

A `HostnameVerifier` that accept any host are often use because of certificate reuse on many hosts. As a consequence, this is vulnerable to [Man-in-the-middle attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) since the client will trust any certificate.

A TrustManager allowing specific certificates (based on a truststore for example) should be built. Wildcard certificates should be created for reused on multiples subdomains. Detailed information for a proper implementation is available at: [[1]](https://stackoverflow.com/a/6378872/89769) [[2]](https://stackoverflow.com/a/5493452/89769)

**Vulnerable Code:**

    public class AllHosts implements HostnameVerifier {
        public boolean verify(final String hostname, final SSLSession session) {
            return true;
        }
    }

**Solution (TrustMangager based on a keystore):**

    KeyStore ks = //Load keystore containing the certificates trusted

    SSLContext sc = SSLContext.getInstance("TLS");

    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
    tmf.init(ks);

    sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(),null);

### References
- [WASC-04: Insufficient Transport Layer Protection](http://projects.webappsec.org/w/page/13246945/Insufficient%20Transport%20Layer%20Protection)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

## Found JAX-WS SOAP endpoint[<small></small>](#JAXWS_ENDPOINT "Permanent link")

_<small>Bug Pattern: <tt>JAXWS_ENDPOINT</tt></small>_

This method is part of a SOAP Web Service (JSR224).

**The security of this web service should be analyzed. For example:**

- Authentication, if enforced, should be tested.
- Access control, if enforced, should be tested.
- The inputs should be tracked for potential vulnerabilities.
- The communication should ideally be over SSL.

### References
- [OWASP: Web Service Security Cheat Sheet](https://www.owasp.org/index.php/Web_Service_Security_Cheat_Sheet)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

## Found JAX-RS REST endpoint[<small></small>](#JAXRS_ENDPOINT "Permanent link")

_<small>Bug Pattern: <tt>JAXRS_ENDPOINT</tt></small>_

This method is part of a REST Web Service (JSR311).

**The security of this web service should be analyzed. For example:**

- Authentication, if enforced, should be tested.
- Access control, if enforced, should be tested.
- The inputs should be tracked for potential vulnerabilities.
- The communication should ideally be over SSL.
- If the service supports writes (e.g., via POST), its vulnerability to CSRF should be investigated.<sup>[1]</sup>

### References
- [OWASP: REST Assessment Cheat Sheet](https://www.owasp.org/index.php/REST_Assessment_Cheat_Sheet)
- [OWASP: REST Security Cheat Sheet](https://www.owasp.org/index.php/REST_Security_Cheat_Sheet)
- [OWASP: Web Service Security Cheat Sheet](https://www.owasp.org/index.php/Web_Service_Security_Cheat_Sheet)
- 1\. [OWASP: Cross-Site Request Forgery](<https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)>)
- [OWASP: CSRF Prevention Cheat Sheet](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29_Prevention_Cheat_Sheet)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

## Found Tapestry page[<small></small>](#TAPESTRY_ENDPOINT "Permanent link")

_<small>Bug Pattern: <tt>TAPESTRY_ENDPOINT</tt></small>_

A Tapestry endpoint was discovered at application startup. Tapestry apps are structured with a backing Java class and a corresponding Tapestry Markup Language page (a `.tml` file) for each page. When a request is received, the GET/POST parameters are mapped to specific inputs in the backing Java class. The mapping is either done with field name:

        [...]
        protected String input;
        [...]

or the definition of an explicit annotation:

        [...]
        @org.apache.tapestry5.annotations.Parameter
        protected String parameter1;

        @org.apache.tapestry5.annotations.Component(id = "password")
        private PasswordField passwordField;
        [...]

The page is mapped to the view `/resources/package/PageName.tml`.

Each Tapestry page in this application should be researched to make sure all inputs that are automatically mapped in this way are properly validated before they are used.

### References
- [Apache Tapestry Home Page](https://tapestry.apache.org/)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

## Found Wicket WebPage[<small></small>](#WICKET_ENDPOINT "Permanent link")

_<small>Bug Pattern: <tt>WICKET_ENDPOINT</tt></small>_

This class represents a Wicket WebPage. Input is automatically read from a PageParameters instance passed to the constructor. The current page is mapped to the view `/package/WebPageName.html`.

Each Wicket page in this application should be researched to make sure all inputs that are automatically mapped in this way are properly validated before they are used.

### References
- [Apache Wicket Home Page](https://wicket.apache.org/)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

## MD2, MD4 and MD5 are weak hash functions[<small></small>](#WEAK_MESSAGE_DIGEST_MD5 "Permanent link")

_<small>Bug Pattern: <tt>WEAK_MESSAGE_DIGEST_MD5</tt></small>_

The algorithms MD2, MD4 and MD5 are not a recommended MessageDigest. **PBKDF2** should be used to hash password for example.

> "The security of the MD5 hash function is severely compromised. A collision attack exists that can find collisions within seconds on a computer with a 2.6 GHz Pentium 4 processor (complexity of 2<sup>24.1</sup>).[1] Further, there is also a chosen-prefix collision attack that can produce a collision for two inputs with specified prefixes within hours, using off-the-shelf computing hardware (complexity 2<sup>39</sup>).[2]"
>
> - [Wikipedia: MD5 - Security](https://en.wikipedia.org/wiki/MD5#Security)

> "**SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256**:
> The use of these hash functions is acceptable for all hash function applications."
>
> - [NIST: Transitioning the Use of Cryptographic Algorithms and Key Lengths p.15](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)

> "The main idea of a PBKDF is to slow dictionary or brute force attacks on the passwords by increasing the time needed to test each password. An attacker with a list of likely passwords can evaluate the PBKDF using the known iteration counter and the salt. Since an attacker has to spend a significant amount of computing time for each try, it becomes harder to apply the dictionary or brute force attacks."
>
> - [NIST: Recommendation for Password-Based Key Derivation p.12](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)

**Vulnerable Code:**

    MessageDigest md5Digest = MessageDigest.getInstance("MD5");
        md5Digest.update(password.getBytes());
        byte[] hashValue = md5Digest.digest();

    byte[] hashValue = DigestUtils.getMd5Digest().digest(password.getBytes());

**Solution (Using bouncy castle):**

    public static byte[] getEncryptedPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        gen.init(password.getBytes("UTF-8"), salt.getBytes(), 4096);
        return ((KeyParameter) gen.generateDerivedParameters(256)).getKey();
    }

**Solution (Java 8 and later):**

    public static byte[] getEncryptedPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 4096, 256 * 8);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return f.generateSecret(spec).getEncoded();
    }

### References
- [1][on collisions for md5](https://www.win.tue.nl/hashclash/On%20Collisions%20for%20MD5%20-%20M.M.J.%20Stevens.pdf): Master Thesis by M.M.J. Stevens
- [2][chosen-prefix collisions for md5 and applications](https://homepages.cwi.nl/~stevens/papers/stJOC%20-%20Chosen-Prefix%20Collisions%20for%20MD5%20and%20Applications.pdf): - Paper written by Marc Stevens
- [Wikipedia: MD5](https://en.wikipedia.org/wiki/MD5)
- [NIST: Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)
- [NIST: Recommendation for Password-Based Key Derivation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
- [Stackoverflow: Reliable implementation of PBKDF2-HMAC-SHA256 for Java](https://stackoverflow.com/q/22580853/89769)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## SHA-1 is a weak hash function[<small></small>](#WEAK_MESSAGE_DIGEST_SHA1 "Permanent link")

_<small>Bug Pattern: <tt>WEAK_MESSAGE_DIGEST_SHA1</tt></small>_

The algorithms SHA-1 is not a recommended algorithm for hash password, for signature verification and other uses. **PBKDF2** should be used to hash password for example.

> "**SHA-1 for digital signature generation:**
> SHA-1 may only be used for digital signature generation where specifically allowed by NIST protocol-specific guidance. For all other applications, <u>SHA-1 shall not be used for digital signature generation</u>.
> **SHA-1 for digital signature verification:**
> For digital signature verification, <u>SHA-1 is allowed for legacy-use</u>.
> [...] > **SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256**:
> The use of these hash functions is acceptable for all hash function applications."
>
> - [NIST: Transitioning the Use of Cryptographic Algorithms and Key Lengths p.15](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)

> "The main idea of a PBKDF is to slow dictionary or brute force attacks on the passwords by increasing the time needed to test each password. An attacker with a list of likely passwords can evaluate the PBKDF using the known iteration counter and the salt. Since an attacker has to spend a significant amount of computing time for each try, it becomes harder to apply the dictionary or brute force attacks."
>
> - [NIST: Recommendation for Password-Based Key Derivation p.12](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)

**Vulnerable Code:**

    MessageDigest sha1Digest = MessageDigest.getInstance("SHA1");
        sha1Digest.update(password.getBytes());
        byte[] hashValue = sha1Digest.digest();

    byte[] hashValue = DigestUtils.getSha1Digest().digest(password.getBytes());

**Solution (Using bouncy castle):**

    public static byte[] getEncryptedPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        gen.init(password.getBytes("UTF-8"), salt.getBytes(), 4096);
        return ((KeyParameter) gen.generateDerivedParameters(256)).getKey();
    }

**Solution (Java 8 and later):**

    public static byte[] getEncryptedPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 4096, 256 * 8);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return f.generateSecret(spec).getEncoded();
    }

### References
- [Qualys blog: SHA1 Deprecation: What You Need to Know](https://community.qualys.com/blogs/securitylabs/2014/09/09/sha1-deprecation-what-you-need-to-know)
- [Google Online Security Blog: Gradually sunsetting SHA-1](https://googleonlinesecurity.blogspot.ca/2014/09/gradually-sunsetting-sha-1.html)
- [NIST: Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)
- [NIST: Recommendation for Password-Based Key Derivation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
- [Stackoverflow: Reliable implementation of PBKDF2-HMAC-SHA256 for Java](https://stackoverflow.com/q/22580853/89769)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## DefaultHttpClient with default constructor is not compatible with TLS 1.2[<small></small>](#DEFAULT_HTTP_CLIENT "Permanent link")

_<small>Bug Pattern: <tt>DEFAULT_HTTP_CLIENT</tt></small>_

**Vulnerable Code:**

    HttpClient client = new DefaultHttpClient();

**Solution:**
Upgrade your implementation to use one of the recommended constructs and configure `https.protocols` JVM option to include TLSv1.2:

- Use [SystemDefaultHttpClient](https://hc.apache.org/httpcomponents-client-ga/httpclient/apidocs/org/apache/http/impl/client/SystemDefaultHttpClient.html) instead

**Sample Code:**

    HttpClient client = new SystemDefaultHttpClient();

- Create an HttpClient based on SSLSocketFactory - get an SSLScoketFactory instance with [`getSystemSocketFactory()`](<https://hc.apache.org/httpcomponents-client-ga/httpclient/apidocs/org/apache/http/conn/ssl/SSLSocketFactory.html#getSystemSocketFactory()>) and use this instance for HttpClient creation
- Create an HttpClient based on SSLConnectionSocketFactory - get an instance with [`getSystemSocketFactory()`](<https://hc.apache.org/httpcomponents-client-ga/httpclient/apidocs/org/apache/http/conn/ssl/SSLConnectionSocketFactory.html#getSystemSocketFactory()>) and use this instance for HttpClient creation
- Use HttpClientBuilder - call [`useSystemProperties()`](<https://hc.apache.org/httpcomponents-client-ga/httpclient/apidocs/org/apache/http/impl/client/HttpClientBuilder.html#useSystemProperties()>) before calling `build()`

**Sample Code:**

    HttpClient client = HttpClientBuilder.create().useSystemProperties().build();

- HttpClients - call [`createSystem()`](<https://hc.apache.org/httpcomponents-client-ga/httpclient/apidocs/org/apache/http/impl/client/HttpClients.html#createSystem()>) to create an instance

**Sample Code:**

    HttpClient client = HttpClients.createSystem();

### References
- [Diagnosing TLS, SSL, and HTTPS](https://blogs.oracle.com/java-platform-group/entry/diagnosing_tls_ssl_and_https)

## Weak SSLContext[<small></small>](#SSL_CONTEXT "Permanent link")

_<small>Bug Pattern: <tt>SSL_CONTEXT</tt></small>_

**Vulnerable Code:**

    SSLContext.getInstance("SSL");

**Solution:**
Upgrade your implementation to the following, and configure `https.protocols` JVM option to include TLSv1.2:

    SSLContext.getInstance("TLS");

### References
- [Diagnosing TLS, SSL, and HTTPS](https://blogs.oracle.com/java-platform-group/entry/diagnosing_tls_ssl_and_https)

## Message digest is custom[<small></small>](#CUSTOM_MESSAGE_DIGEST "Permanent link")

_<small>Bug Pattern: <tt>CUSTOM_MESSAGE_DIGEST</tt></small>_

Implementing a custom MessageDigest is error-prone.

[NIST](https://csrc.nist.gov/projects/hash-functions) recommends the use of SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, or SHA-512/256.

> "**SHA-1 for digital signature generation:**
> SHA-1 may only be used for digital signature generation where specifically allowed by NIST protocol-specific guidance. For all other applications, <u>SHA-1 shall not be used for digital signature generation</u>.
> **SHA-1 for digital signature verification:**
> For digital signature verification, <u>SHA-1 is allowed for legacy-use</u>.
> [...] > **SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256**:
> The use of these hash functions is acceptable for all hash function applications."
>
> - [NIST: Transitioning the Use of Cryptographic Algorithms and Key Lengths p.15](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)

**Vulnerable Code:**

    MyProprietaryMessageDigest extends MessageDigest {
        @Override
        protected byte[] engineDigest() {
            [...]
            //Creativity is a bad idea
            return [...];
        }
    }

Upgrade your implementation to use one of the approved algorithms. Use an algorithm that is sufficiently strong for your specific security needs.

**Example Solution:**

    MessageDigest sha256Digest = MessageDigest.getInstance("SHA256");
    sha256Digest.update(password.getBytes());

### References
- [NIST Approved Hash Functions](https://csrc.nist.gov/projects/hash-functions)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Tainted filename read[<small></small>](#FILE_UPLOAD_FILENAME "Permanent link")

_<small>Bug Pattern: <tt>FILE_UPLOAD_FILENAME</tt></small>_

The filename provided by the FileUpload API can be tampered with by the client to reference unauthorized files.

For example:

- `"../../../config/overide_file"`
- `"shell.jsp\u0000expected.gif"`

Therefore, such values should not be passed directly to the filesystem API. If acceptable, the application should generate its own file names and use those. Otherwise, the provided filename should be properly validated to ensure it's properly structured, contains no unauthorized path characters (e.g., / \), and refers to an authorized file.

### References
- [Securiteam: File upload security recommendations](https://blogs.securiteam.com/index.php/archives/1268)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [WASC-33: Path Traversal](http://projects.webappsec.org/w/page/13246952/Path%20Traversal)
- [OWASP: Path Traversal](https://www.owasp.org/index.php/Path_Traversal)
- [CAPEC-126: Path Traversal](https://capec.mitre.org/data/definitions/126.html)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

## Regex DOS (ReDOS)[<small></small>](#REDOS "Permanent link")

_<small>Bug Pattern: <tt>REDOS</tt></small>_

Regular expressions (Regex) are frequently subject to Denial of Service (DOS) attacks (called ReDOS). This is due to the fact that regex engines may take a large amount of time when analyzing certain strings, depending on how the regex is defined.

For example, for the regex: `^(a+)+<section, the input "`aaaaaaaaaaaaaaaaX`" will cause the regex engine to analyze 65536 different paths.<sup>[1] Example taken from OWASP references</sup>

Therefore, it is possible that a single request may cause a large amount of computation on the server side. The problem with this regex, and others like it, is that there are two different ways the same input character can be accepted by the Regex due to the `+` (or a `*`) inside the parenthesis, and the `+` (or a `*`) outside the parenthesis. The way this is written, either `+` could consume the character 'a'. To fix this, the regex should be rewritten to eliminate the ambiguity. For example, this could simply be rewritten as: `^a+<section, which is presumably what the author meant anyway (any number of a's). Assuming that's what the original regex meant, this new regex can be evaluated quickly, and is not subject to ReDOS.

### References
- [Sebastian Kubeck's Weblog: Detecting and Preventing ReDoS Vulnerabilities](https://sebastiankuebeck.wordpress.com/2011/03/01/detecting-and-preventing-redos-vulnerabilities/)
- <sup>[1]</sup> [OWASP: Regular expression Denial of Service](https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS)
- [CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')](https://cwe.mitre.org/data/definitions/400.html)

## XML parsing vulnerable to XXE (XMLStreamReader)[<small></small>](#XXE_XMLSTREAMREADER "Permanent link")

_<small>Bug Pattern: <tt>XXE_XMLSTREAMREADER</tt></small>_

### Attack

XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source.

**Risk 1: Expose local file content (XXE: <u>X</u>ML E<u>x</u>ternal <u>E</u>ntity)**

    <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
       <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
    <foo>&xxe;</foo>

**Risk 2: Denial of service (XEE: <u>X</u>ML <u>E</u>ntity <u>E</u>xpansion)**

    <?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ELEMENT lolz (#PCDATA)>
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    [...]
     <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <lolz>&lol9;</lolz>

### Solution

In order to avoid exposing dangerous feature of the XML parser, you can do the following change to the code.

**Vulnerable Code:**

    public void parseXML(InputStream input) throws XMLStreamException {

        XMLInputFactory factory = XMLInputFactory.newFactory();
        XMLStreamReader reader = factory.createXMLStreamReader(input);
        [...]
    }

The following snippets show two available solutions. You can set one property or both.

**Solution disabling External Entities:**

    public void parseXML(InputStream input) throws XMLStreamException {

        XMLInputFactory factory = XMLInputFactory.newFactory();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        XMLStreamReader reader = factory.createXMLStreamReader(input);
        [...]
    }

**Solution disabling DTD:**

    public void parseXML(InputStream input) throws XMLStreamException {

        XMLInputFactory factory = XMLInputFactory.newFactory();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = factory.createXMLStreamReader(input);
        [...]
    }

### References
- [CWE-611: Improper Restriction of XML External Entity Reference ('XXE')](https://cwe.mitre.org/data/definitions/611.html)
- [CERT: IDS10-J. Prevent XML external entity attacks](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=61702260)
- [OWASP.org: XML External Entity (XXE) Processing](https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing)
- [WS-Attacks.org: XML Entity Expansion](https://www.ws-attacks.org/index.php/XML_Entity_Expansion)
- [WS-Attacks.org: XML External Entity DOS](https://www.ws-attacks.org/index.php/XML_External_Entity_DOS)
- [WS-Attacks.org: XML Entity Reference Attack](https://www.ws-attacks.org/index.php/XML_Entity_Reference_Attack)
- [Identifying XML External Entity vulnerability (XXE)](https://blog.h3xstream.com/2014/06/identifying-xml-external-entity.html)
- [JEP 185: Restrict Fetching of External XML Resources](https://openjdk.java.net/jeps/185)

## XML parsing vulnerable to XXE (XPathExpression)[<small></small>](#XXE_XPATH "Permanent link")

_<small>Bug Pattern: <tt>XXE_XPATH</tt></small>_

### Attack

XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source.

**Risk 1: Expose local file content (XXE: <u>X</u>ML E<u>x</u>ternal <u>E</u>ntity)**

    <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
       <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
    <foo>&xxe;</foo>

**Risk 2: Denial of service (XEE: <u>X</u>ML <u>E</u>ntity <u>E</u>xpansion)**

    <?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ELEMENT lolz (#PCDATA)>
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    [...]
     <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <lolz>&lol9;</lolz>

### Solution

In order to avoid exposing dangerous feature of the XML parser, you can do the following change to the code.

**Vulnerable Code:**

    DocumentBuilder builder = df.newDocumentBuilder();

    XPathFactory xPathFactory = XPathFactory.newInstance();
    XPath xpath = xPathFactory.newXPath();
    XPathExpression xPathExpr = xpath.compile("/somepath/text()");

    xPathExpr.evaluate(new InputSource(inputStream));

The following snippets show two available solutions. You can set one feature or both.

**Solution using "Secure processing" mode:**

This setting will protect you against Denial of Service attack and remote file access.

    DocumentBuilderFactory df = DocumentBuilderFactory.newInstance();
    df.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    DocumentBuilder builder = df.newDocumentBuilder();

    [...]

    xPathExpr.evaluate( builder.parse(inputStream) );

**Solution disabling DTD:**

By disabling DTD, almost all XXE attacks will be prevented.

    DocumentBuilderFactory df = DocumentBuilderFactory.newInstance();
    spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    DocumentBuilder builder = df.newDocumentBuilder();

    [...]

    xPathExpr.evaluate( builder.parse(inputStream) );

### References
- [CWE-611: Improper Restriction of XML External Entity Reference ('XXE')](https://cwe.mitre.org/data/definitions/611.html)
- [CERT: IDS10-J. Prevent XML external entity attacks](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=61702260)
- [OWASP.org: XML External Entity (XXE) Processing](https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing)
- [WS-Attacks.org: XML Entity Expansion](https://www.ws-attacks.org/index.php/XML_Entity_Expansion)
- [WS-Attacks.org: XML External Entity DOS](https://www.ws-attacks.org/index.php/XML_External_Entity_DOS)
- [WS-Attacks.org: XML Entity Reference Attack](https://www.ws-attacks.org/index.php/XML_Entity_Reference_Attack)
- [Identifying XML External Entity vulnerability (XXE)](https://blog.h3xstream.com/2014/06/identifying-xml-external-entity.html)
- [XML External Entity (XXE) Prevention Cheat Sheet](<https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet#XPathExpression>)

## XML parsing vulnerable to XXE (SAXParser)[<small></small>](#XXE_SAXPARSER "Permanent link")

_<small>Bug Pattern: <tt>XXE_SAXPARSER</tt></small>_

### Attack

XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source.

**Risk 1: Expose local file content (XXE: <u>X</u>ML E<u>x</u>ternal <u>E</u>ntity)**

    <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
       <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
    <foo>&xxe;</foo>

**Risk 2: Denial of service (XEE: <u>X</u>ML <u>E</u>ntity <u>E</u>xpansion)**

    <?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ELEMENT lolz (#PCDATA)>
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    [...]
     <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <lolz>&lol9;</lolz>

### Solution

In order to avoid exposing dangerous feature of the XML parser, you can do the following change to the code.

**Vulnerable Code:**

    SAXParser parser = SAXParserFactory.newInstance().newSAXParser();

    parser.parse(inputStream, customHandler);

The following snippets show two available solutions. You can set one feature or both.

**Solution using "Secure processing" mode:**

This setting will protect you against Denial of Service attack and remote file access.

    SAXParserFactory spf = SAXParserFactory.newInstance();
    spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    SAXParser parser = spf.newSAXParser();

    parser.parse(inputStream, customHandler);

**Solution disabling DTD:**

By disabling DTD, almost all XXE attacks will be prevented.

    SAXParserFactory spf = SAXParserFactory.newInstance();
    spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    SAXParser parser = spf.newSAXParser();

    parser.parse(inputStream, customHandler);

### References
- [CWE-611: Improper Restriction of XML External Entity Reference ('XXE')](https://cwe.mitre.org/data/definitions/611.html)
- [CERT: IDS10-J. Prevent XML external entity attacks](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=61702260)
- [OWASP.org: XML External Entity (XXE) Processing](https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing)
- [WS-Attacks.org: XML Entity Expansion](https://www.ws-attacks.org/index.php/XML_Entity_Expansion)
- [WS-Attacks.org: XML External Entity DOS](https://www.ws-attacks.org/index.php/XML_External_Entity_DOS)
- [WS-Attacks.org: XML Entity Reference Attack](https://www.ws-attacks.org/index.php/XML_Entity_Reference_Attack)
- [Identifying XML External Entity vulnerability (XXE)](https://blog.h3xstream.com/2014/06/identifying-xml-external-entity.html)
- [Xerces complete features list](https://xerces.apache.org/xerces-j/features.html)

## XML parsing vulnerable to XXE (XMLReader)[<small></small>](#XXE_XMLREADER "Permanent link")

_<small>Bug Pattern: <tt>XXE_XMLREADER</tt></small>_

### Attack

XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source.

**Risk 1: Expose local file content (XXE: <u>X</u>ML E<u>x</u>ternal <u>E</u>ntity)**

    <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
       <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
    <foo>&xxe;</foo>

**Risk 2: Denial of service (XEE: <u>X</u>ML <u>E</u>ntity <u>E</u>xpansion)**

    <?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ELEMENT lolz (#PCDATA)>
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    [...]
     <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <lolz>&lol9;</lolz>

### Solution

In order to avoid exposing dangerous feature of the XML parser, you can do the following change to the code.

**Vulnerable Code:**

    XMLReader reader = XMLReaderFactory.createXMLReader();
    reader.setContentHandler(customHandler);
    reader.parse(new InputSource(inputStream));

The following snippets show two available solutions. You can set one property or both.

**Solution using "Secure processing" mode:**

This setting will protect you against Denial of Service attack and remote file access.

    XMLReader reader = XMLReaderFactory.createXMLReader();
    reader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    reader.setContentHandler(customHandler);

    reader.parse(new InputSource(inputStream));

**Solution disabling DTD:**

By disabling DTD, almost all XXE attacks will be prevented.

    XMLReader reader = XMLReaderFactory.createXMLReader();
    reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    reader.setContentHandler(customHandler);

    reader.parse(new InputSource(inputStream));

### References
- [CWE-611: Improper Restriction of XML External Entity Reference ('XXE')](https://cwe.mitre.org/data/definitions/611.html)
- [CERT: IDS10-J. Prevent XML external entity attacks](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=61702260)
- [OWASP.org: XML External Entity (XXE) Processing](https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing)
- [WS-Attacks.org: XML Entity Expansion](https://www.ws-attacks.org/index.php/XML_Entity_Expansion)
- [WS-Attacks.org: XML External Entity DOS](https://www.ws-attacks.org/index.php/XML_External_Entity_DOS)
- [WS-Attacks.org: XML Entity Reference Attack](https://www.ws-attacks.org/index.php/XML_Entity_Reference_Attack)
- [Identifying XML External Entity vulnerability (XXE)](https://blog.h3xstream.com/2014/06/identifying-xml-external-entity.html)
- [Xerces complete features list](https://xerces.apache.org/xerces-j/features.html)

## XML parsing vulnerable to XXE (DocumentBuilder)[<small></small>](#XXE_DOCUMENT "Permanent link")

_<small>Bug Pattern: <tt>XXE_DOCUMENT</tt></small>_

### Attack

XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source.

**Risk 1: Expose local file content (XXE: <u>X</u>ML E<u>x</u>ternal <u>E</u>ntity)**

    <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
       <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
    <foo>&xxe;</foo>

**Risk 2: Denial of service (XEE: <u>X</u>ML <u>E</u>ntity <u>E</u>xpansion)**

    <?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ELEMENT lolz (#PCDATA)>
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    [...]
     <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <lolz>&lol9;</lolz>

### Solution

In order to avoid exposing dangerous feature of the XML parser, you can do the following change to the code.

**Vulnerable Code:**

    DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();

    Document doc = db.parse(input);

The following snippets show two available solutions. You can set one feature or both.

**Solution using "Secure processing" mode:**

This setting will protect you against Denial of Service attack and remote file access.

    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    DocumentBuilder db = dbf.newDocumentBuilder();

    Document doc = db.parse(input);

**Solution disabling DTD:**

By disabling DTD, almost all XXE attacks will be prevented.

    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    DocumentBuilder db = dbf.newDocumentBuilder();

    Document doc = db.parse(input);

### References
- [CWE-611: Improper Restriction of XML External Entity Reference ('XXE')](https://cwe.mitre.org/data/definitions/611.html)
- [CERT: IDS10-J. Prevent XML external entity attacks](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=61702260)
- [OWASP.org: XML External Entity (XXE) Processing](https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing)
- [WS-Attacks.org: XML Entity Expansion](https://www.ws-attacks.org/index.php/XML_Entity_Expansion)
- [WS-Attacks.org: XML External Entity DOS](https://www.ws-attacks.org/index.php/XML_External_Entity_DOS)
- [WS-Attacks.org: XML Entity Reference Attack](https://www.ws-attacks.org/index.php/XML_Entity_Reference_Attack)
- [Identifying XML External Entity vulnerability (XXE)](https://blog.h3xstream.com/2014/06/identifying-xml-external-entity.html)
- [Xerces2 complete features list](http://xerces.apache.org/xerces2-j/features.html)

## XML parsing vulnerable to XXE (TransformerFactory)[<small></small>](#XXE_DTD_TRANSFORM_FACTORY "Permanent link")

_<small>Bug Pattern: <tt>XXE_DTD_TRANSFORM_FACTORY</tt></small>_

### Attack

XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source.

**Risk 1: Expose local file content (XXE: <u>X</u>ML E<u>x</u>ternal <u>E</u>ntity)**

    <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
       <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
    <foo>&xxe;</foo>

**Risk 2: Denial of service (XEE: <u>X</u>ML <u>E</u>ntity <u>E</u>xpansion)**

    <?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ELEMENT lolz (#PCDATA)>
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    [...]
     <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <lolz>&lol9;</lolz>

### Solution

In order to avoid exposing dangerous feature of the XML parser, you can do the following change to the code.

**Vulnerable Code:**

    Transformer transformer = TransformerFactory.newInstance().newTransformer();
    transformer.transform(input, result);

The following snippets show two available solutions. You can set one feature or both.

**Solution using "Secure processing" mode:**

This setting will protect you against remote file access but not denial of service.

    TransformerFactory factory = TransformerFactory.newInstance();
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "all");

    Transformer transformer = factory.newTransformer();
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");

    transformer.transform(input, result);

**Solution disabling DTD:**

This setting will protect you against remote file access but not denial of service.

    TransformerFactory factory = TransformerFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

    Transformer transformer = factory.newTransformer();
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");

    transformer.transform(input, result);

### References
- [CWE-611: Improper Restriction of XML External Entity Reference ('XXE')](https://cwe.mitre.org/data/definitions/611.html)
- [CERT: IDS10-J. Prevent XML external entity attacks](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=61702260)
- [OWASP.org: XML External Entity (XXE) Processing](https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing)
- [WS-Attacks.org: XML Entity Expansion](https://www.ws-attacks.org/index.php/XML_Entity_Expansion)
- [WS-Attacks.org: XML External Entity DOS](https://www.ws-attacks.org/index.php/XML_External_Entity_DOS)
- [WS-Attacks.org: XML Entity Reference Attack](https://www.ws-attacks.org/index.php/XML_Entity_Reference_Attack)
- [Identifying XML External Entity vulnerability (XXE)](https://blog.h3xstream.com/2014/06/identifying-xml-external-entity.html)

## XSLT parsing vulnerable to XXE (TransformerFactory)[<small></small>](#XXE_XSLT_TRANSFORM_FACTORY "Permanent link")

_<small>Bug Pattern: <tt>XXE_XSLT_TRANSFORM_FACTORY</tt></small>_

### Attack

XSLT External Entity (XXE) attacks can occur when an XSLT parser supports external entities while processing XSLT received from an untrusted source.

**Risk: Expose local file content (XXE: <u>X</u>ML E<u>x</u>ternal <u>E</u>ntity)**

    <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
       <xsl:template match="/">
           <xsl:value-of select="document('/etc/passwd')">
       </xsl:value-of></xsl:template>
    </xsl:stylesheet>

### Solution

In order to avoid exposing dangerous feature of the XML parser, you can do the following change to the code.

**Vulnerable Code:**

    Transformer transformer = TransformerFactory.newInstance().newTransformer();
    transformer.transform(input, result);

The following snippets show two available solutions. You can set one feature or both.

**Solution using "Secure processing" mode:**

This setting will protect you against remote file access but not denial of service.

    TransformerFactory factory = TransformerFactory.newInstance();
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "all");

    Transformer transformer = factory.newTransformer();
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");

    transformer.transform(input, result);

**Solution disabling DTD:**

This setting will protect you against remote file access but not denial of service.

    TransformerFactory factory = TransformerFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

    Transformer transformer = factory.newTransformer();
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");

    transformer.transform(input, result);

### References
- [CWE-611: Improper Restriction of XML External Entity Reference ('XXE')](https://cwe.mitre.org/data/definitions/611.html)
- [CERT: IDS10-J. Prevent XML external entity attacks](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=61702260)
- [OWASP.org: XML External Entity (XXE) Processing](https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing)
- [WS-Attacks.org: XML Entity Expansion](https://www.ws-attacks.org/index.php/XML_Entity_Expansion)
- [WS-Attacks.org: XML External Entity DOS](https://www.ws-attacks.org/index.php/XML_External_Entity_DOS)
- [WS-Attacks.org: XML Entity Reference Attack](https://www.ws-attacks.org/index.php/XML_Entity_Reference_Attack)
- [Identifying XML External Entity vulnerability (XXE)](https://blog.h3xstream.com/2014/06/identifying-xml-external-entity.html)

## Potential XPath Injection[<small></small>](#XPATH_INJECTION "Permanent link")

_<small>Bug Pattern: <tt>XPATH_INJECTION</tt></small>_

XPath injection risks are similar to SQL injection. If the XPath query contains untrusted user input, the complete data source could be exposed. This could allow an attacker to access unauthorized data or maliciously modify the target XML.

### References
- [WASC-39: XPath Injection](http://projects.webappsec.org/w/page/13246963/SQL%20Injection)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)
- [CERT: IDS09-J. Prevent XPath Injection (archive)](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=61407250)
- [Black Hat Europe 2012: Hacking XPath 2.0](https://media.blackhat.com/bh-eu-12/Siddharth/bh-eu-12-Siddharth-Xpath-WP.pdf)
- [Balisage.net: XQuery Injection](https://www.balisage.net/Proceedings/vol7/html/Vlist02/BalisageVol7-Vlist02.html)

## Found Struts 1 endpoint[<small></small>](#STRUTS1_ENDPOINT "Permanent link")

_<small>Bug Pattern: <tt>STRUTS1_ENDPOINT</tt></small>_

This class is a Struts 1 Action.

Once a request is routed to this controller, a Form object will automatically be instantiated that contains the HTTP parameters. The use of these parameters should be reviewed to make sure they are used safely.

## Found Struts 2 endpoint[<small></small>](#STRUTS2_ENDPOINT "Permanent link")

_<small>Bug Pattern: <tt>STRUTS2_ENDPOINT</tt></small>_

In Struts 2, the endpoints are Plain Old Java Objects (POJO) which means no Interface/Class needs to be implemented/extended.

When a request is routed to its controller (like the selected class), the supplied HTTP parameters are automatically mapped to setters for the class. Therefore, all setters of this class should be considered as untrusted input even if the form doesn't include those values. An attacker can simply provide additional values in the request, and they will be set in the object anyway, as long as that object has such a setter. The use of these parameters should be reviewed to make sure they are used safely.

## Found Spring endpoint[<small></small>](#SPRING_ENDPOINT "Permanent link")

_<small>Bug Pattern: <tt>SPRING_ENDPOINT</tt></small>_

This class is a Spring Controller. All methods annotated with `RequestMapping` (as well as its shortcut annotations `GetMapping`, `PostMapping`, `PutMapping`, `DeleteMapping`, and `PatchMapping`) are reachable remotely. This class should be analyzed to make sure that remotely exposed methods are safe to expose to potential attackers.

## Spring CSRF protection disabled[<small></small>](#SPRING_CSRF_PROTECTION_DISABLED "Permanent link")

_<small>Bug Pattern: <tt>SPRING_CSRF_PROTECTION_DISABLED</tt></small>_

Disabling Spring Security's CSRF protection is unsafe for standard web applications.

A valid use case for disabling this protection would be a service exposing state-changing operations that is guaranteed to be used only by non-browser clients.

**Insecure configuration:**

    @EnableWebSecurity
    public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.csrf().disable();
        }
    }

### References
- [Spring Security Official Documentation: When to use CSRF protection](https://docs.spring.io/spring-security/site/docs/current/reference/html/csrf.- html#when-to-use-csrf-protection)
- [OWASP: Cross-Site Request Forgery](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29)
- [OWASP: CSRF Prevention Cheat Sheet](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29_Prevention_Cheat_Sheet)
- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

## Spring CSRF unrestricted RequestMapping[<small></small>](#SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING "Permanent link")

_<small>Bug Pattern: <tt>SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING</tt></small>_

Methods annotated with `RequestMapping` are by default mapped to all the HTTP request methods. However, Spring Security's CSRF protection is not enabled by default for the HTTP request methods `GET`, `HEAD`, `TRACE`, and `OPTIONS` (as this could cause the tokens to be leaked). Therefore, state-changing methods annotated with `RequestMapping` and not narrowing the mapping to the HTTP request methods `POST`, `PUT`, `DELETE`, or `PATCH` are vulnerable to CSRF attacks.

**Vulnerable Code:**

    @Controller
    public class UnsafeController {

        @RequestMapping("/path")
        public void writeData() {
            // State-changing operations performed within this method.
        }
    }

**Solution (Spring Framework 4.3 and later):**

    @Controller
    public class SafeController {

        /**
         * For methods without side-effects use @GetMapping.
         */
        @GetMapping("/path")
        public String readData() {
            // No state-changing operations performed within this method.
            return "";
        }

        /**
         * For state-changing methods use either @PostMapping, @PutMapping, @DeleteMapping, or @PatchMapping.
         */
        @PostMapping("/path")
        public void writeData() {
            // State-changing operations performed within this method.
        }
    }

**Solution (Before Spring Framework 4.3):**

    @Controller
    public class SafeController {

        /**
         * For methods without side-effects use either
         * RequestMethod.GET, RequestMethod.HEAD, RequestMethod.TRACE, or RequestMethod.OPTIONS.
         */
        @RequestMapping(value = "/path", method = RequestMethod.GET)
        public String readData() {
            // No state-changing operations performed within this method.
            return "";
        }

        /**
         * For state-changing methods use either
         * RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, or RequestMethod.PATCH.
         */
        @RequestMapping(value = "/path", method = RequestMethod.POST)
        public void writeData() {
            // State-changing operations performed within this method.
        }
    }

### References
- [Spring Security Official Documentation: Use proper HTTP verbs (CSRF protection)](https://docs.spring.io/spring-security/site/docs/current/reference/html/csrf.- html#csrf-use-proper-verbs)
- [OWASP: Cross-Site Request Forgery](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29)
- [OWASP: CSRF Prevention Cheat Sheet](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29_Prevention_Cheat_Sheet)
- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

## Potential injection (custom)[<small></small>](#CUSTOM_INJECTION "Permanent link")

_<small>Bug Pattern: <tt>CUSTOM_INJECTION</tt></small>_

The method identified is susceptible to injection. The input should be validated and properly escaped.

**Vulnerable code samples:**

    SqlUtil.execQuery("select * from UserEntity t where id = " + parameterInput);

Refer to the online wiki for detailed instructions on [how to configure custom signatures](https://github.com/find-sec-bugs/find-sec-bugs/wiki/Custom-signatures).

### References
- [WASC-19: SQL Injection](http://projects.webappsec.org/w/page/13246963/SQL%20Injection)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [OWASP: SQL Injection Prevention Cheat Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
- [OWASP: Query Parameterization Cheat Sheet](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)

## Potential SQL Injection[<small></small>](#SQL_INJECTION "Permanent link")

_<small>Bug Pattern: <tt>SQL_INJECTION</tt></small>_

The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. Alternatively to prepare statements, each parameter can be escaped manually.

**Vulnerable Code:**

    createQuery("select * from User where id = '"+inputId+"'");

**Solution:**

    import org.owasp.esapi.Encoder;

    createQuery("select * from User where id = '"+Encoder.encodeForSQL(inputId)+"'");

**References (SQL injection)**
- [WASC-19: SQL Injection](http://projects.webappsec.org/w/page/13246963/SQL%20Injection)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [OWASP: SQL Injection Prevention Cheat Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
- [OWASP: Query Parameterization Cheat Sheet](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)

## Potential SQL Injection with Turbine[<small></small>](#SQL_INJECTION_TURBINE "Permanent link")

_<small>Bug Pattern: <tt>SQL_INJECTION_TURBINE</tt></small>_

The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. Turbine API provide a DSL to build query with Java code.

**Vulnerable Code:**

    List<Record> BasePeer.executeQuery( "select * from Customer where id=" + inputId );

**Solution (using Criteria DSL):**

    Criteria c = new Criteria();
    c.add( CustomerPeer.ID, inputId );

    List<Customer> customers = CustomerPeer.doSelect( c );

**Solution (using specialized method):**

    Customer customer = CustomerPeer.retrieveByPK( new NumberKey( inputId ) );

**Solution (using OWASP Encoder):**

    import org.owasp.esapi.Encoder;

    BasePeer.executeQuery("select * from Customer where id = '"+Encoder.encodeForSQL(inputId)+"'");

**References (Turbine)**
- [Turbine Documentation: Criteria Howto](https://turbine.apache.org/turbine/turbine-2.1/howto/criteria-howto.html)
**References (SQL injection)**
- [WASC-19: SQL Injection](http://projects.webappsec.org/w/page/13246963/SQL%20Injection)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [OWASP: SQL Injection Prevention Cheat Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
- [OWASP: Query Parameterization Cheat Sheet](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)

## Potential SQL/HQL Injection (Hibernate)[<small></small>](#SQL_INJECTION_HIBERNATE "Permanent link")

_<small>Bug Pattern: <tt>SQL_INJECTION_HIBERNATE</tt></small>_

The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection. Alternatively to prepare statements, Hibernate Criteria can be used.

**Vulnerable Code:**

    Session session = sessionFactory.openSession();
    Query q = session.createQuery("select t from UserEntity t where id = " + input);
    q.execute();

**Solution:**

    Session session = sessionFactory.openSession();
    Query q = session.createQuery("select t from UserEntity t where id = :userId");
    q.setString("userId",input);
    q.execute();

**Solution for dynamic queries (with Hibernate Criteria):**

    Session session = sessionFactory.openSession();
    Query q = session.createCriteria(UserEntity.class)
        .add( Restrictions.like("id", input) )
        .list();
    q.execute();

**References (Hibernate)**
- [CWE-564: SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)
- [Hibernate Documentation: Query Criteria](https://docs.jboss.org/hibernate/orm/3.3/reference/en/html/querycriteria.html)
- [Hibernate Javadoc: Query Object](https://docs.jboss.org/hibernate/orm/3.2/api/org/hibernate/Query.html)
- [HQL for pentesters](https://blog.h3xstream.com/2014/02/hql-for-pentesters.html): Guideline to test if the suspected code is exploitable.
**References (SQL injection)**
- [WASC-19: SQL Injection](http://projects.webappsec.org/w/page/13246963/SQL%20Injection)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [OWASP: SQL Injection Prevention Cheat Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
- [OWASP: Query Parameterization Cheat Sheet](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)

## Potential SQL/JDOQL Injection (JDO)[<small></small>](#SQL_INJECTION_JDO "Permanent link")

_<small>Bug Pattern: <tt>SQL_INJECTION_JDO</tt></small>_

The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection.

**Vulnerable Code:**

    PersistenceManager pm = getPM();

    Query q = pm.newQuery("select * from Users where name = " + input);
    q.execute();

**Solution:**

    PersistenceManager pm = getPM();

    Query q = pm.newQuery("select * from Users where name = nameParam");
    q.declareParameters("String nameParam");
    q.execute(input);

**References (JDO)**
- [JDO: Object Retrieval](https://db.apache.org/jdo/object_retrieval.html)
**References (SQL injection)**
- [WASC-19: SQL Injection](http://projects.webappsec.org/w/page/13246963/SQL%20Injection)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [OWASP: SQL Injection Prevention Cheat Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
- [OWASP: Query Parameterization Cheat Sheet](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)

## Potential SQL/JPQL Injection (JPA)[<small></small>](#SQL_INJECTION_JPA "Permanent link")

_<small>Bug Pattern: <tt>SQL_INJECTION_JPA</tt></small>_

The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection.

**Vulnerable Code:**

    EntityManager pm = getEM();

    TypedQuery<UserEntity> q = em.createQuery(
        String.format("select * from Users where name = %s", username),
        UserEntity.class);

    UserEntity res = q.getSingleResult();

**Solution:**

    TypedQuery<UserEntity> q = em.createQuery(
        "select * from Users where name = usernameParam",UserEntity.class)
        .setParameter("usernameParam", username);

    UserEntity res = q.getSingleResult();

**References (JPA)**
- [The Java EE 6 Tutorial: Creating Queries Using the Java Persistence Query Language](https://docs.oracle.com/javaee/6/tutorial/doc/bnbrg.html)
**References (SQL injection)**
- [WASC-19: SQL Injection](http://projects.webappsec.org/w/page/13246963/SQL%20Injection)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [OWASP: SQL Injection Prevention Cheat Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
- [OWASP: Query Parameterization Cheat Sheet](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)

## Potential JDBC Injection (Spring JDBC)[<small></small>](#SQL_INJECTION_SPRING_JDBC "Permanent link")

_<small>Bug Pattern: <tt>SQL_INJECTION_SPRING_JDBC</tt></small>_

The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection.

**Vulnerable Code:**

    JdbcTemplate jdbc = new JdbcTemplate();
    int count = jdbc.queryForObject("select count(*) from Users where name = '"+paramName+"'", Integer.class);

**Solution:**

    JdbcTemplate jdbc = new JdbcTemplate();
    int count = jdbc.queryForObject("select count(*) from Users where name = ?", Integer.class, paramName);

**References (Spring JDBC)**
- [Spring Official Documentation: Data access with JDBC](https://spring.io/guides/gs/relational-data-access/)
**References (SQL injection)**
- [WASC-19: SQL Injection](http://projects.webappsec.org/w/page/13246963/SQL%20Injection)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [OWASP: SQL Injection Prevention Cheat Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
- [OWASP: Query Parameterization Cheat Sheet](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)

## Potential JDBC Injection[<small></small>](#SQL_INJECTION_JDBC "Permanent link")

_<small>Bug Pattern: <tt>SQL_INJECTION_JDBC</tt></small>_

The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection.

**Vulnerable Code:**

    Connection conn = [...];
    Statement stmt = con.createStatement();
    ResultSet rs = stmt.executeQuery("update COFFEES set SALES = "+nbSales+" where COF_NAME = '"+coffeeName+"'");

**Solution:**

    Connection conn = [...];
    conn.prepareStatement("update COFFEES set SALES = ? where COF_NAME = ?");
    updateSales.setInt(1, nbSales);
    updateSales.setString(2, coffeeName);

**References (JDBC)**
- [Oracle Documentation: The Java Tutorials > Prepared Statements](https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html)
**References (SQL injection)**
- [WASC-19: SQL Injection](http://projects.webappsec.org/w/page/13246963/SQL%20Injection)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [OWASP: SQL Injection Prevention Cheat Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
- [OWASP: Query Parameterization Cheat Sheet](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)

## Potential Scala Slick Injection[<small></small>](#SCALA_SQL_INJECTION_SLICK "Permanent link")

_<small>Bug Pattern: <tt>SCALA_SQL_INJECTION_SLICK</tt></small>_

The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection.

**Vulnerable Code:**

    db.run {
      sql"select * from people where name = '#$value'".as[Person]
    }

**Solution:**

    db.run {
      sql"select * from people where name = $value".as[Person]
    }

**References (SQL injection)**
- [WASC-19: SQL Injection](http://projects.webappsec.org/w/page/13246963/SQL%20Injection)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [OWASP: SQL Injection Prevention Cheat Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
- [OWASP: Query Parameterization Cheat Sheet](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)

## Potential Scala Anorm Injection[<small></small>](#SCALA_SQL_INJECTION_ANORM "Permanent link")

_<small>Bug Pattern: <tt>SCALA_SQL_INJECTION_ANORM</tt></small>_

The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection.

**Vulnerable Code:**

    val peopleParser = Macro.parser[Person]("id", "name", "age")

    DB.withConnection { implicit c =>
      val people: List[Person] = SQL("select * from people where name = '" + value + "'").as(peopleParser.*)
    }

**Solution:**

    val peopleParser = Macro.parser[Person]("id", "name", "age")

    DB.withConnection { implicit c =>
      val people: List[Person] = SQL"select * from people where name = $value".as(peopleParser.*)
    }

**References (SQL injection)**
- [WASC-19: SQL Injection](http://projects.webappsec.org/w/page/13246963/SQL%20Injection)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [OWASP: SQL Injection Prevention Cheat Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
- [OWASP: Query Parameterization Cheat Sheet](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)

## Potential Android SQL Injection[<small></small>](#SQL_INJECTION_ANDROID "Permanent link")

_<small>Bug Pattern: <tt>SQL_INJECTION_ANDROID</tt></small>_

The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection.

**Vulnerable Code:**

    String query = "SELECT * FROM  messages WHERE uid= '"+userInput+"'" ;
    Cursor cursor = this.getReadableDatabase().rawQuery(query,null);

**Solution:**

    String query = "SELECT * FROM  messages WHERE uid= ?" ;
    Cursor cursor = this.getReadableDatabase().rawQuery(query,new String[] {userInput});

**References (Android SQLite)**
- [InformIT.com: Practical Advice for Building Secure Android Databases in SQLite](http://www.informit.com/articles/article.aspx?p=2268753&seqNum=5)
- [Packtpub.com: Knowing the SQL-injection attacks and securing our Android applications from them](https://www.packtpub.com/books/content/- knowing-sql-injection-attacks-and-securing-our-android-applications-them)
- [Android Database Support (Enterprise Android: Programming Android Database Applications for the Enterprise)](https://books.google.ca/books?id=SXlMAQAAQBAJ&lpg=PR1&- pg=PA64#v=onepage&q&f=false)
- [Safe example of Insert, Select, Update and Delete queries provided by Suragch](https://stackoverflow.com/a/29797229/89769)
**References (SQL injection)**
- [WASC-19: SQL Injection](http://projects.webappsec.org/w/page/13246963/SQL%20Injection)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [OWASP: SQL Injection Prevention Cheat Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
- [OWASP: Query Parameterization Cheat Sheet](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)

## Potential LDAP Injection[<small></small>](#LDAP_INJECTION "Permanent link")

_<small>Bug Pattern: <tt>LDAP_INJECTION</tt></small>_

Just like SQL, all inputs passed to an LDAP query need to be passed in safely. Unfortunately, LDAP doesn't have prepared statement interfaces like SQL. Therefore, the primary defense against LDAP injection is strong input validation of any untrusted data before including it in an LDAP query.

**Code at risk:**

    NamingEnumeration<SearchResult> answers = context.search("dc=People,dc=example,dc=com",
            "(uid=" + username + ")", ctrls);

### References
- [WASC-29: LDAP Injection](http://projects.webappsec.org/w/page/13246947/LDAP%20Injection)
- [OWASP: Top 10 2013-A1-Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection)
- [CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)
- [LDAP Injection Guide: Learn How to Detect LDAP Injections and Improve LDAP Security](https://www.veracode.com/security/ldap-injection)

## Potential code injection when using Script Engine[<small></small>](#SCRIPT_ENGINE_INJECTION "Permanent link")

_<small>Bug Pattern: <tt>SCRIPT_ENGINE_INJECTION</tt></small>_

Dynamic code is being evaluate. A careful analysis of the code construction should be made. Malicious code execution could lead to data leakage or operating system compromised.

If the evaluation of user code is intended, a proper sandboxing should be applied (see references).

**Code at risk:**

    public void runCustomTrigger(String script) {
        ScriptEngineManager factory = new ScriptEngineManager();
        ScriptEngine engine = factory.getEngineByName("JavaScript");

        engine.eval(script); //Bad things can happen here.
    }

**Solution:**

Safe evaluation of JavaScript code using "Cloudbees Rhino Sandbox" library.

    public void runCustomTrigger(String script) {
        SandboxContextFactory contextFactory = new SandboxContextFactory();
        Context context = contextFactory.makeContext();
        contextFactory.enterContext(context);
        try {
            ScriptableObject prototype = context.initStandardObjects();
            prototype.setParentScope(null);
            Scriptable scope = context.newObject(prototype);
            scope.setPrototype(prototype);

            context.evaluateString(scope,script, null, -1, null);
        } finally {
            context.exit();
        }
    }

### References
- [Cloudbees Rhino Sandbox](https://github.com/cloudbees/rhino-sandbox): Utility to create sandbox with Rhino (block access to all classes)
- [CodeUtopia.net: Sandboxing Rhino in Java](https://codeutopia.net/blog/2009/01/02/sandboxing-rhino-in-java/)
- [Remote Code Execution .. by design](https://blog.h3xstream.com/2014/11/remote-code-execution-by-design.html): Example of malicious payload. The samples given could be used to test sandboxing rules.
- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

## Potential code injection when using Spring Expression[<small></small>](#SPEL_INJECTION "Permanent link")

_<small>Bug Pattern: <tt>SPEL_INJECTION</tt></small>_

A Spring expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.

**Code at risk:**

    public void parseExpressionInterface(Person personObj,String property) {

            ExpressionParser parser = new SpelExpressionParser();

            //Unsafe if the input is control by the user..
            Expression exp = parser.parseExpression(property+" == 'Albert'");

            StandardEvaluationContext testContext = new StandardEvaluationContext(personObj);
            boolean result = exp.getValue(testContext, Boolean.class);
    [...]

### References
- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)
- [Spring Expression Language (SpEL) - Official Documentation](https://docs.spring.io/spring-framework/docs/3.2.x/spring-framework-reference/html/expressions.html)
- [Minded Security: Expression Language Injection](https://www.mindedsecurity.com/fileshare/ExpressionLanguageInjection.pdf)
- [Remote Code Execution .. by design](https://blog.h3xstream.com/2014/11/remote-code-execution-by-design.html): Example of malicious payload. The samples given could be used to test sandboxing rules.
- [Spring Data-Commons: (CVE-2018-1273)](https://gosecure.net/2018/05/15/beware-of-the-magic-spell-part-1-cve-2018-1273/)
- [Spring OAuth2: CVE-2018-1260](https://gosecure.net/2018/05/17/beware-of-the-magic-spell-part-2-cve-2018-1260/)

## Potential code injection when using Expression Language (EL)[<small></small>](#EL_INJECTION "Permanent link")

_<small>Bug Pattern: <tt>EL_INJECTION</tt></small>_

An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.

**Code at risk:**

    public void evaluateExpression(String expression) {
        FacesContext context = FacesContext.getCurrentInstance();
        ExpressionFactory expressionFactory = context.getApplication().getExpressionFactory();
        ELContext elContext = context.getELContext();
        ValueExpression vex = expressionFactory.createValueExpression(elContext, expression, String.class);
        return (String) vex.getValue(elContext);
    }

### References
- [Minded Security: Abusing EL for executing OS commands](https://blog.mindedsecurity.com/2015/11/reliable-os-shell-with-el-expression.html)
- [The Java EE 6 Tutorial: Expression Language](https://docs.oracle.com/javaee/6/tutorial/doc/gjddd.html)
- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)
- [Minded Security: Expression Language Injection](https://www.mindedsecurity.com/fileshare/ExpressionLanguageInjection.pdf)
- [Dan Amodio's blog: Remote Code with Expression Language Injection](http://danamodio.com/appsec/research/spring-remote-code-with-expression-language-injection/)
- [Remote Code Execution .. by design](https://blog.h3xstream.com/2014/11/remote-code-execution-by-design.html): Example of malicious payload. The samples given could be used to test sandboxing rules.

## Potential code injection in Seam logging call[<small></small>](#SEAM_LOG_INJECTION "Permanent link")

_<small>Bug Pattern: <tt>SEAM_LOG_INJECTION</tt></small>_

Seam Logging API support an expression language to introduce bean property to log messages. The expression language can also be the source to unwanted code execution.

In this context, an expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.

**Code at risk:**

    public void logUser(User user) {
        log.info("Current logged in user : " + user.getUsername());
        //...
    }

**Solution:**

    public void logUser(User user) {
        log.info("Current logged in user : #0", user.getUsername());
        //...
    }

### References
- [JBSEAM-5130: Issue documenting the risk](https://issues.jboss.org/browse/JBSEAM-5130)
- [JBoss Seam: Logging (Official documentation)](https://docs.jboss.org/seam/2.3.1.Final/reference/html_single/#d0e4185)
- [The Java EE 6 Tutorial: Expression Language](https://docs.oracle.com/javaee/6/tutorial/doc/gjddd.html)
- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

## Potential code injection when using OGNL expression[<small></small>](#OGNL_INJECTION "Permanent link")

_<small>Bug Pattern: <tt>OGNL_INJECTION</tt></small>_

A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.

**Code at risk:**

    public void getUserProperty(String property) {
      [...]
      //The first argument is the dynamic expression.
      return ognlUtil.getValue("user."+property, ctx, root, String.class);
    }

**Solution:**

In general, method evaluating OGNL expression should not receive user input. It is intended to be used in static configurations and JSP.

### References
- [HP Enterprise: Struts 2 OGNL Expression Injections by Alvaro MuÃ±oz](https://community.saas.hpe.com/t5/Security-Research/Struts-2-OGNL-Expression-Injections/ba-p/288881)
- [Gotham Digital Science: An Analysis Of CVE-2017-5638](https://blog.gdssecurity.com/labs/2017/3/27/an-analysis-of-cve-2017-5638.html)
- [Apache Struts2: Vulnerability S2-016](https://struts.apache.org/docs/s2-016.html)
- [Apache Struts 2 Documentation: OGNL](https://struts.apache.org/docs/ognl.html)

## Potential HTTP Response Splitting[<small></small>](#HTTP_RESPONSE_SPLITTING "Permanent link")

_<small>Bug Pattern: <tt>HTTP_RESPONSE_SPLITTING</tt></small>_

When an HTTP request contains unexpected `CR` and `LF` characters, the server may respond with an output stream that is interpreted as two different HTTP responses (instead of one). An attacker can control the second response and mount attacks such as cross-site scripting and cache poisoning attacks. According to OWASP, the issue has been fixed in virtually all modern Java EE application servers, but it is still better to validate the input. If you are concerned about this risk, you should test on the platform of concern to see if the underlying platform allows for `CR` or `LF` characters to be injected into headers. This weakness is reported with low priority because it requires the web container to be vulnerable.

**Code at risk:**

    String author = request.getParameter(AUTHOR_PARAMETER);
    // ...
    Cookie cookie = new Cookie("author", author);
    response.addCookie(cookie);

### References
- [OWASP: HTTP Response Splitting](https://www.owasp.org/index.php/HTTP_Response_Splitting)
- [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html) [CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)

## Potential CRLF Injection for logs[<small></small>](#CRLF_INJECTION_LOGS "Permanent link")

_<small>Bug Pattern: <tt>CRLF_INJECTION_LOGS</tt></small>_

When data from an untrusted source is put into a logger and not neutralized correctly, an attacker could forge log entries or include malicious content. Inserted false entries could be used to skew statistics, distract the administrator or even to implicate another party in the commission of a malicious act. If the log file is processed automatically, the attacker can render the file unusable by corrupting the format of the file or injecting unexpected characters. An attacker may also inject code or other commands into the log file and take advantage of a vulnerability in the log processing utility (e.g. command injection or XSS).

**Code at risk:**

    String val = request.getParameter("user");
    String metadata = request.getParameter("metadata");
    [...]
    if(authenticated) {
        log.info("User " + val + " (" + metadata + ") was authenticated successfully");
    }
    else {
        log.info("User " + val + " (" + metadata + ") was not authenticated");
    }

A malicious user could send the metadata parameter with the value: `"Firefox) was authenticated successfully\r\n[INFO] User bbb (Internet Explorer"`.**Solution:**

You can manually sanitize each parameter.

    log.info("User " + val.replaceAll("[\r\n]","") + " (" + userAgent.replaceAll("[\r\n]","") + ") was not authenticated");

You can also configure your logger service to replace new line for all message events. Here is sample configuration for LogBack [using the `replace` function](https://logback.qos.ch/manual/layouts.html#replace).

    <pattern>%-5level - %replace(%msg){'[\r\n]', ''}%n</pattern>

Finally, you can use a logger implementation that replace new line by spaces. The project [OWASP Security Logging](https://github.com/javabeanz/owasp-security-logging) has an implementation for Logback and Log4j.

### References
- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)
- [CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://logback.qos.ch/manual/layouts.html#replace)
- [OWASP Security Logging](https://github.com/javabeanz/owasp-security-logging)

## Potential external control of configuration[<small></small>](#EXTERNAL_CONFIG_CONTROL "Permanent link")

_<small>Bug Pattern: <tt>EXTERNAL_CONFIG_CONTROL</tt></small>_

Allowing external control of system settings can disrupt service or cause an application to behave in unexpected, and potentially malicious ways. An attacker could cause an error by providing a nonexistent catalog name or connect to an unauthorized portion of the database.

**Code at risk:**

    conn.setCatalog(request.getParameter("catalog"));

### References
- [CWE-15: External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

## Bad hexadecimal concatenation[<small></small>](#BAD_HEXA_CONVERSION "Permanent link")

_<small>Bug Pattern: <tt>BAD_HEXA_CONVERSION</tt></small>_

When converting a byte array containing a hash signature to a human readable string, a conversion mistake can be made if the array is read byte by byte. The following sample illustrates the use of the method `Integer.toHexString()` which will trim any leading zeroes from each byte of the computed hash value.

    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] resultBytes = md.digest(password.getBytes("UTF-8"));

    StringBuilder stringBuilder = new StringBuilder();
    for(byte b :resultBytes) {
        stringBuilder.append( Integer.toHexString( b & 0xFF ) );
    }

    return stringBuilder.toString();

This mistake weakens the hash value computed since it introduces more collisions. For example, the hash values "0x0679" and "0x6709" would both output as "679" for the above function.

In this situation, the method `Integer.toHexString()` should be replaced with `String.format()` as follows:

    stringBuilder.append( String.format( "%02X", b ) );

### References
- [CWE-704: Incorrect Type Conversion or Cast](https://cwe.mitre.org/data/definitions/704.html)

## Hazelcast symmetric encryption[<small></small>](#HAZELCAST_SYMMETRIC_ENCRYPTION "Permanent link")

_<small>Bug Pattern: <tt>HAZELCAST_SYMMETRIC_ENCRYPTION</tt></small>_

The network communications for Hazelcast is configured to use a symmetric cipher (probably DES or Blowfish).

Those ciphers alone do not provide integrity or secure authentication. The use of asymmetric encryption is preferred.

### References
- [WASC-04: Insufficient Transport Layer Protection](http://projects.webappsec.org/w/page/13246945/Insufficient%20Transport%20Layer%20Protection)
- [Hazelcast Documentation: Encryption](https://docs.hazelcast.org/docs/3.5/manual/html/encryption.html)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

## NullCipher is insecure[<small></small>](#NULL_CIPHER "Permanent link")

_<small>Bug Pattern: <tt>NULL_CIPHER</tt></small>_

The NullCipher is rarely used intentionally in production applications. It implements the Cipher interface by returning ciphertext identical to the supplied plaintext. In a few contexts, such as testing, a NullCipher may be appropriate.

**Vulnerable Code:**

    Cipher doNothingCihper = new NullCipher();
    [...]
    //The ciphertext produced will be identical to the plaintext.
    byte[] cipherText = c.doFinal(plainText);

**Solution:**
Avoid using the NullCipher. Its accidental use can introduce a significant confidentiality risk.

### References
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

## Unencrypted Socket[<small></small>](#UNENCRYPTED_SOCKET "Permanent link")

_<small>Bug Pattern: <tt>UNENCRYPTED_SOCKET</tt></small>_

The communication channel used is not encrypted. The traffic could be read by an attacker intercepting the network traffic.

**Vulnerable Code:**
Plain socket (Cleartext communication):

    Socket soc = new Socket("www.google.com",80);

**Solution:**
SSL Socket (Secure communication):

    Socket soc = SSLSocketFactory.getDefault().createSocket("www.google.com", 443);

Beyond using an SSL socket, you need to make sure your use of SSLSocketFactory does all the appropriate certificate validation checks to make sure you are not subject to man-in-the-middle attacks. Please read the OWASP Transport Layer Protection Cheat Sheet for details on how to do this correctly.

### References
- [OWASP: Top 10 2010-A9-Insufficient Transport Layer Protection](https://www.owasp.org/index.php/Top_10_2010-A9)
- [OWASP: Top 10 2013-A6-Sensitive Data Exposure](https://www.owasp.org/index.php/Top_10_2013-A6-Sensitive_Data_Exposure)
- [OWASP: Transport Layer Protection Cheat Sheet](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
- [WASC-04: Insufficient Transport Layer Protection](http://projects.webappsec.org/w/page/13246945/Insufficient%20Transport%20Layer%20Protection)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

## Unencrypted Server Socket[<small></small>](#UNENCRYPTED_SERVER_SOCKET "Permanent link")

_<small>Bug Pattern: <tt>UNENCRYPTED_SERVER_SOCKET</tt></small>_

The communication channel used is not encrypted. The traffic could be read by an attacker intercepting the network traffic.

**Vulnerable Code:**
Plain server socket (Cleartext communication):

    ServerSocket soc = new ServerSocket(1234);

**Solution:**
SSL Server Socket (Secure communication):

    ServerSocket soc = SSLServerSocketFactory.getDefault().createServerSocket(1234);

Beyond using an SSL server socket, you need to make sure your use of SSLServerSocketFactory does all the appropriate certificate validation checks to make sure you are not subject to man-in-the-middle attacks. Please read the OWASP Transport Layer Protection Cheat Sheet for details on how to do this correctly.

### References
- [OWASP: Top 10 2010-A9-Insufficient Transport Layer Protection](https://www.owasp.org/index.php/Top_10_2010-A9)
- [OWASP: Top 10 2013-A6-Sensitive Data Exposure](https://www.owasp.org/index.php/Top_10_2013-A6-Sensitive_Data_Exposure)
- [OWASP: Transport Layer Protection Cheat Sheet](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
- [WASC-04: Insufficient Transport Layer Protection](http://projects.webappsec.org/w/page/13246945/Insufficient%20Transport%20Layer%20Protection)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

## DES is insecure[<small></small>](#DES_USAGE "Permanent link")

_<small>Bug Pattern: <tt>DES_USAGE</tt></small>_

DES is considered strong ciphers for modern applications. Currently, NIST recommends the usage of AES block ciphers instead of DES.

**Example weak code:**

    Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
    c.init(Cipher.ENCRYPT_MODE, k, iv);
    byte[] cipherText = c.doFinal(plainText);

**Example solution:**

    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, k, iv);
    byte[] cipherText = c.doFinal(plainText);

### References
- [NIST Withdraws Outdated Data Encryption Standard](https://www.nist.gov/news-events/news/2005/06/nist-withdraws-outdated-data-encryption-standard)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

## DESede is insecure[<small></small>](#TDES_USAGE "Permanent link")

_<small>Bug Pattern: <tt>TDES_USAGE</tt></small>_

Triple DES (also known as 3DES or DESede) is considered strong ciphers for modern applications. Currently, NIST recommends the usage of AES block ciphers instead of 3DES.

**Example weak code:**

    Cipher c = Cipher.getInstance("DESede/ECB/PKCS5Padding");
    c.init(Cipher.ENCRYPT_MODE, k, iv);
    byte[] cipherText = c.doFinal(plainText);

**Example solution:**

    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, k, iv);
    byte[] cipherText = c.doFinal(plainText);

### References
- [NIST Withdraws Outdated Data Encryption Standard](https://www.nist.gov/news-events/news/2005/06/nist-withdraws-outdated-data-encryption-standard)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

## RSA with no padding is insecure[<small></small>](#RSA_NO_PADDING "Permanent link")

_<small>Bug Pattern: <tt>RSA_NO_PADDING</tt></small>_

The software uses the RSA algorithm but does not incorporate Optimal Asymmetric Encryption Padding (OAEP), which might weaken the encryption.

**Vulnerable Code:**

    Cipher.getInstance("RSA/NONE/NoPadding")

**Solution:**
The code should be replaced with:

    Cipher.getInstance("RSA/ECB/OAEPWithMD5AndMGF1Padding")

### References
- [CWE-780: Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)
- [Root Labs: Why RSA encryption padding is critical](https://rdist.root.org/2009/10/06/why-rsa-encryption-padding-is-critical/)

## Hard coded password[<small></small>](#HARD_CODE_PASSWORD "Permanent link")

_<small>Bug Pattern: <tt>HARD_CODE_PASSWORD</tt></small>_

Passwords should not be kept in the source code. The source code can be widely shared in an enterprise environment, and is certainly shared in open source. To be managed safely, passwords and secret keys should be stored in separate configuration files or keystores. (Hard coded keys are reported separately by _Hard Coded Key_ pattern)

**Vulnerable Code:**

    private String SECRET_PASSWORD = "letMeIn!";

    Properties props = new Properties();
    props.put(Context.SECURITY_CREDENTIALS, "p@ssw0rd");

### References
- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

## Hard coded key[<small></small>](#HARD_CODE_KEY "Permanent link")

_<small>Bug Pattern: <tt>HARD_CODE_KEY</tt></small>_

Cryptographic keys should not be kept in the source code. The source code can be widely shared in an enterprise environment, and is certainly shared in open source. To be managed safely, passwords and secret keys should be stored in separate configuration files or keystores. (Hard coded passwords are reported separately by the _Hard coded password_ pattern)

**Vulnerable Code:**

    byte[] key = {1, 2, 3, 4, 5, 6, 7, 8};
    SecretKeySpec spec = new SecretKeySpec(key, "AES");
    Cipher aes = Cipher.getInstance("AES");
    aes.init(Cipher.ENCRYPT_MODE, spec);
    return aesCipher.doFinal(secretData);

### References
- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

## Unsafe hash equals[<small></small>](#UNSAFE_HASH_EQUALS "Permanent link")

_<small>Bug Pattern: <tt>UNSAFE_HASH_EQUALS</tt></small>_

An attacker might be able to detect the value of the secret hash due to the exposure of comparison timing. When the functions `Arrays.equals()` or `String.equals()` are called, they will exit earlier if fewer bytes are matched.

**Vulnerable Code:**

    String actualHash = ...

    if(userInput.equals(actualHash)) {
        ...
    }

**Solution:**

    String actualHash = ...

    if(MessageDigest.isEqual(userInput.getBytes(),actualHash.getBytes())) {
        ...
    }

### References
- [CWE-203: Information Exposure Through DiscrepancyKey](https://cwe.mitre.org/data/definitions/203.html)

## Struts Form without input validation[<small></small>](#STRUTS_FORM_VALIDATION "Permanent link")

_<small>Bug Pattern: <tt>STRUTS_FORM_VALIDATION</tt></small>_

Form inputs should have minimal input validation. Preventive validation helps provide defense in depth against a variety of risks.

Validation can be introduced by implementing a `validate` method.

    public class RegistrationForm extends ValidatorForm {

        private String name;
        private String email;

        [...]

        public ActionErrors validate(ActionMapping mapping, HttpServletRequest request) {
            //Validation code for name and email parameters passed in via the HttpRequest goes here
        }
    }

### References
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-106: Struts: Plug-in Framework not in Use](https://cwe.mitre.org/data/definitions/106.html)

## XSSRequestWrapper is a weak XSS protection[<small></small>](#XSS_REQUEST_WRAPPER "Permanent link")

_<small>Bug Pattern: <tt>XSS_REQUEST_WRAPPER</tt></small>_

An implementation of `HttpServletRequestWrapper` called `XSSRequestWrapper` was published through various blog sites. <sup>[[1]](https://java.dzone.com/articles/stronger-anti-cross-site)</sup> <sup>[[2]](https://www.javacodegeeks.com/2012/07/anti-cross-site-scripting-xss-filter.html)</sup>

The filtering is weak for a few reasons:

- It covers only parameters not headers and side-channel inputs
- The chain of replace functions can be bypassed easily (see example below)
- It's a black list of very specific bad patterns (rather than a white list of good/valid input)

**Example of bypass:**

    <scrivbscript:pt>ale rt ( 1 )</scrivbscript:pt>

The previous input will be transformed into **`"<script >al ert ( 1 )</ script>"`**. The removal of `"vbscript:"` is after the replacement of `"<sc ript>.*</scri pt>"`.

For stronger protection, choose a solution that encodes characters automatically in the **<u>view</u>** (template or JSP) following the XSS protection rules defined in the OWASP XSS Prevention Cheat Sheet.

### References
- [WASC-8: Cross Site Scripting](http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting)
- [OWASP: XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet)
- [OWASP: Top 10 2013-A3: Cross-Site Scripting (XSS)](https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_%28XSS%29)
- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

## Blowfish usage with short key[<small></small>](#BLOWFISH_KEY_SIZE "Permanent link")

_<small>Bug Pattern: <tt>BLOWFISH_KEY_SIZE</tt></small>_

The Blowfish cipher supports key sizes from 32 bits to 448 bits. A small key size makes the ciphertext vulnerable to brute force attacks. At least 128 bits of entropy should be used when generating the key if use of Blowfish is required.

If the algorithm can be changed, the AES block cipher should be used instead.

**Vulnerable Code:**

    KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
    keyGen.init(64);

**Solution:**

    KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
    keyGen.init(128);

### References
- [Blowfish (cipher)](<https://en.wikipedia.org/wiki/Blowfish_(cipher)>)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

## RSA usage with short key[<small></small>](#RSA_KEY_SIZE "Permanent link")

_<small>Bug Pattern: <tt>RSA_KEY_SIZE</tt></small>_

The NIST recommends the use of <u>2048 bits and higher</u> keys for the RSA algorithm.

> "Digital Signature Verification | RSA: `1024 ≤ len(n) < 2048` | Legacy-use"
> "Digital Signature Verification | RSA: `len(n) ≥ 2048` | Acceptable"
>
> - [NIST: Recommendation for Transitioning the Use of Cryptographic Algorithms and Key Lengths p.7](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)

**Vulnerable Code:**

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(512);

**Solution:**
The KeyPairGenerator creation should be as follows with at least 2048 bit key size.

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);

### References
- [NIST: Latest publication on key management](https://csrc.nist.gov/projects/key-management)
- [NIST: Recommendation for Transitioning the Use of Cryptographic Algorithms and Key Lengths p.7](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)
- [Wikipedia: Asymmetric algorithm key lengths](https://en.wikipedia.org/wiki/Key_size#Asymmetric%5Falgorithm%5Fkey%5Flengths)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [Keylength.com (BlueKrypt): Aggregate key length recommendations.](https://www.keylength.com/en/compare/)

## Unvalidated Redirect[<small></small>](#UNVALIDATED_REDIRECT "Permanent link")

_<small>Bug Pattern: <tt>UNVALIDATED_REDIRECT</tt></small>_

Unvalidated redirects occur when an application redirects a user to a destination URL specified by a user supplied parameter that is not validated. Such vulnerabilities can be used to facilitate phishing attacks.

**Scenario**
1\. A user is tricked into visiting the malicious URL: `http://website.com/login?redirect=http://evil.vvebsite.com/fake/login`
2\. The user is redirected to a fake login page that looks like a site they trust. (`http://evil.vvebsite.com/fake/login`)
3\. The user enters his credentials.
4\. The evil site steals the user's credentials and redirects him to the original website.

This attack is plausible because most users don't double check the URL after the redirection. Also, redirection to an authentication page is very common.

**Vulnerable Code:**

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        [...]
        resp.sendRedirect(req.getParameter("redirectUrl"));
        [...]
    }

**Solution/Countermeasures:**

- Don't accept redirection destinations from users
- Accept a destination key, and use it to look up the target (legal) destination
- Accept only relative paths
- White list URLs (if possible)
- Validate that the beginning of the URL is part of a white list

### References
- [WASC-38: URL Redirector Abuse](http://projects.webappsec.org/w/page/13246981/URL%20Redirector%20Abuse)
- [OWASP: Top 10 2013-A10: Unvalidated Redirects and Forwards](https://www.owasp.org/index.php/Top_10_2013-A10-Unvalidated_Redirects_and_Forwards)
- [OWASP: Unvalidated Redirects and Forwards Cheat Sheet](https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

## Unvalidated Redirect (Play Framework)[<small></small>](#PLAY_UNVALIDATED_REDIRECT "Permanent link")

_<small>Bug Pattern: <tt>PLAY_UNVALIDATED_REDIRECT</tt></small>_

Unvalidated redirects occur when an application redirects a user to a destination URL specified by a user supplied parameter that is not validated. Such vulnerabilities can be used to facilitate phishing attacks.

**Scenario**
1\. A user is tricked into visiting the malicious URL: `http://website.com/login?redirect=http://evil.vvebsite.com/fake/login`
2\. The user is redirected to a fake login page that looks like a site they trust. (`http://evil.vvebsite.com/fake/login`)
3\. The user enters his credentials.
4\. The evil site steals the user's credentials and redirects him to the original website.

This attack is plausible because most users don't double check the URL after the redirection. Also, redirection to an authentication page is very common.

**Vulnerable Code:**

    def login(redirectUrl:String) = Action {
        [...]
        Redirect(url)
    }

**Solution/Countermeasures:**

- Don't accept redirection destinations from users
- Accept a destination key, and use it to look up the target (legal) destination
- Accept only relative paths
- White list URLs (if possible)
- Validate that the beginning of the URL is part of a white list

### References
- [WASC-38: URL Redirector Abuse](http://projects.webappsec.org/w/page/13246981/URL%20Redirector%20Abuse)
- [OWASP: Top 10 2013-A10: Unvalidated Redirects and Forwards](https://www.owasp.org/index.php/Top_10_2013-A10-Unvalidated_Redirects_and_Forwards)
- [OWASP: Unvalidated Redirects and Forwards Cheat Sheet](https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

## Spring Unvalidated Redirect[<small></small>](#SPRING_UNVALIDATED_REDIRECT "Permanent link")

_<small>Bug Pattern: <tt>SPRING_UNVALIDATED_REDIRECT</tt></small>_

Unvalidated redirects occur when an application redirects a user to a destination URL specified by a user supplied parameter that is not validated. Such vulnerabilities can be used to facilitate phishing attacks.

**Scenario**
1\. A user is tricked into visiting the malicious URL: `http://website.com/login?redirect=http://evil.vvebsite.com/fake/login`
2\. The user is redirected to a fake login page that looks like a site they trust. (`http://evil.vvebsite.com/fake/login`)
3\. The user enters his credentials.
4\. The evil site steals the user's credentials and redirects him to the original website.

This attack is plausible because most users don't double check the URL after the redirection. Also, redirection to an authentication page is very common.

**Vulnerable Code:**

    @RequestMapping("/redirect")
    public String redirect(@RequestParam("url") String url) {
        [...]
        return "redirect:" + url;
    }

**Solution/Countermeasures:**

- Don't accept redirection destinations from users
- Accept a destination key, and use it to look up the target (legal) destination
- Accept only relative paths
- White list URLs (if possible)
- Validate that the beginning of the URL is part of a white list

### References
- [WASC-38: URL Redirector Abuse](http://projects.webappsec.org/w/page/13246981/URL%20Redirector%20Abuse)
- [OWASP: Top 10 2013-A10: Unvalidated Redirects and Forwards](https://www.owasp.org/index.php/Top_10_2013-A10-Unvalidated_Redirects_and_Forwards)
- [OWASP: Unvalidated Redirects and Forwards Cheat Sheet](https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

## Unexpected property leak[<small></small>](#ENTITY_LEAK "Permanent link")

_<small>Bug Pattern: <tt>ENTITY_LEAK</tt></small>_

Persistent objects should never be returned by APIs. They might lead to leaking business logic over the UI, unauthorized tampering of persistent objects in database.

**Vulnerable Code:**

    @javax.persistence.Entity
    class UserEntity {

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        private String username;

        private String password;
    }

    [...]
    @Controller
    class UserController {

        @GetMapping("/user/{id}")
        public UserEntity getUser(@PathVariable("id") String id) {

            return userService.findById(id).get(); //Return the user entity with ALL fields.
        }

    }

**Solution/Countermeasures:**

- Data transfer objects should be used instead including only the parameters needed as input/response to/from the API.
- Sensitive parameters should be removed properly before transferring to UI.
- Data should be persisted in database only after proper sanitisation checks.

**Spring MVC Solution:**
In Spring specifically, you can apply the following solution to allow or disallow specific fields.

    @Controller
    class UserController {

       @InitBinder
       public void initBinder(WebDataBinder binder, WebRequest request)
       {
          binder.setAllowedFields(["username","firstname","lastname"]);
       }

    }

### References
- [OWASP Top 10-2017 A3: Sensitive Data Exposure](https://www.owasp.org/index.php/Top_10-2017_A3-Sensitive_Data_Exposure)
- [OWASP Cheat Sheet: Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html#spring-mvc)
- [CWE-212: Improper Cross-boundary Removal of Sensitive Data](https://cwe.mitre.org/data/definitions/212.html)
- [CWE-213: Intentional Information Exposure](https://cwe.mitre.org/data/definitions/213.html)

## Mass assignment[<small></small>](#ENTITY_MASS_ASSIGNMENT "Permanent link")

_<small>Bug Pattern: <tt>ENTITY_MASS_ASSIGNMENT</tt></small>_

Persistent objects should never be returned by APIs. They might lead to leaking business logic over the UI, unauthorized tampering of persistent objects in database.

**Vulnerable Code:**

    @javax.persistence.Entity
    class UserEntity {

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        private String username;

        private String password;

        private Long role;
    }

    [...]
    @Controller
    class UserController {

        @PutMapping("/user/")
        @ResponseStatus(value = HttpStatus.OK)
        public void update(UserEntity user) {

            userService.save(user); //ALL fields from the user can be altered
        }

    }

**General Guidelines:**

- Data transfer objects should be used instead including only the parameters needed as input/response to/from the API.
- Sensitive parameters should be removed properly before transferring to UI.
- Data should be persisted in database only after proper sanitisation checks.

**Spring MVC Solution:**
In Spring specifically, you can apply the following solution to allow or disallow specific fields.

With whitelist:

    @Controller
    class UserController {

       @InitBinder
       public void initBinder(WebDataBinder binder, WebRequest request)
       {
          binder.setAllowedFields(["username","password"]);
       }

    }

With a blacklist:

    @Controller
    class UserController {

       @InitBinder
       public void initBinder(WebDataBinder binder, WebRequest request)
       {
          binder.setDisallowedFields(["role"]);
       }

    }

### References
- [OWASP Cheat Sheet: Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html#spring-mvc)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

## Dynamic JSP inclusion[<small></small>](#JSP_INCLUDE "Permanent link")

_<small>Bug Pattern: <tt>JSP_INCLUDE</tt></small>_

The inclusion of JSP file allow the entry of dynamic value. It may allow an attacker to control the JSP page included. If this is the case, an attacker will try to include a file on disk that he controls. By including arbitrary files, the attacker gets the ability to execute any code.

**Vulnerable Code:**

    <jsp:include page="${param.secret_param}" />

**Solution:**

    <c:if test="${param.secret_param == 'page1'}">
        <jsp:include page="page1.jsp" />
    </c:if>

### References
- [InfosecInstitute: File Inclusion Attacks](https://resources.infosecinstitute.com/file-inclusion-attacks/)
- [WASC-05: Remote File Inclusion](http://projects.webappsec.org/w/page/13246955/Remote%20File%20Inclusion)

## Dynamic variable in Spring expression[<small></small>](#JSP_SPRING_EVAL "Permanent link")

_<small>Bug Pattern: <tt>JSP_SPRING_EVAL</tt></small>_

A Spring expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.

**Vulnerable Code:**

    <%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>

    <spring:eval expression="${param.lang}" var="lang" />

    <%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>

    <spring:eval expression="'${param.lang}'=='fr'" var="languageIsFrench" />

**Solution:**

    <c:set var="lang" value="${param.lang}"/>

    <c:set var="languageIsFrench" value="${param.lang == 'fr'}"/>

### References
- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

## Escaping of special XML characters is disabled[<small></small>](#JSP_JSTL_OUT "Permanent link")

_<small>Bug Pattern: <tt>JSP_JSTL_OUT</tt></small>_

A potential XSS was found. It could be used to execute unwanted JavaScript in a client's browser. (See references)

**Vulnerable Code:**

    <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

    <c:out value="${param.test_param}" escapeXml="false"/>

**Solution:**

    <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

    <c:out value="${param.test_param}"/>

### References
- [WASC-8: Cross Site Scripting](http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting)
- [OWASP: XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet)
- [OWASP: Top 10 2013-A3: Cross-Site Scripting (XSS)](https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_%28XSS%29)
- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [JSTL Javadoc: Out tag](https://docs.oracle.com/javaee/5/jstl/1.1/docs/tlddocs/c/out.html)

## Potential XSS in JSP[<small></small>](#XSS_JSP_PRINT "Permanent link")

_<small>Bug Pattern: <tt>XSS_JSP_PRINT</tt></small>_

A potential XSS was found. It could be used to execute unwanted JavaScript in a client's browser. (See references)

**Vulnerable Code:**

    <%
    String taintedInput = (String) request.getAttribute("input");
    %>
    [...]
    <%= taintedInput %>

**Solution:**

    <%
    String taintedInput = (String) request.getAttribute("input");
    %>
    [...]
    <%= Encode.forHtml(taintedInput) %>

The best defense against XSS is context sensitive output encoding like the example above. There are typically 4 contexts to consider: HTML, JavaScript, CSS (styles), and URLs. Please follow the XSS protection rules defined in the OWASP XSS Prevention Cheat Sheet, which explains these defenses in significant detail.

### References
- [WASC-8: Cross Site Scripting](http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting)
- [OWASP: XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet)
- [OWASP: Top 10 2013-A3: Cross-Site Scripting (XSS)](https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_%28XSS%29)
- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Java Encoder](https://code.google.com/p/owasp-java-encoder/)

## Potential XSS in Servlet[<small></small>](#XSS_SERVLET "Permanent link")

_<small>Bug Pattern: <tt>XSS_SERVLET</tt></small>_

A potential XSS was found. It could be used to execute unwanted JavaScript in a client's browser. (See references)

**Vulnerable Code:**

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String input1 = req.getParameter("input1");
        [...]
        resp.getWriter().write(input1);
    }

**Solution:**

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String input1 = req.getParameter("input1");
        [...]
        resp.getWriter().write(Encode.forHtml(input1));
    }

The best defense against XSS is context sensitive output encoding like the example above. There are typically 4 contexts to consider: HTML, JavaScript, CSS (styles), and URLs. Please follow the XSS protection rules defined in the OWASP XSS Prevention Cheat Sheet, which explains these defenses in significant detail.

Note that this XSS in Servlet rule looks for similar issues, but looks for them in a different way than the existing 'XSS: Servlet reflected cross site scripting vulnerability' and 'XSS: Servlet reflected cross site scripting vulnerability in error page' rules in FindBugs.

### References
- [WASC-8: Cross Site Scripting](http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting)
- [OWASP: XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet)
- [OWASP: Top 10 2013-A3: Cross-Site Scripting (XSS)](https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_%28XSS%29)
- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Java Encoder](https://code.google.com/p/owasp-java-encoder/)

## XMLDecoder usage[<small></small>](#XML_DECODER "Permanent link")

_<small>Bug Pattern: <tt>XML_DECODER</tt></small>_

XMLDecoder should not be used to parse untrusted data. Deserializing user input can lead to arbitrary code execution. This is possible because XMLDecoder supports arbitrary method invocation. This capability is intended to call setter methods, but in practice, any method can be called.

**Malicious XML example:**

    <?xml version="1.0" encoding="UTF-8" ?>
    <java version="1.4.0" class="java.beans.XMLDecoder">
      <object class="java.io.PrintWriter">
        <string>/tmp/Hacked.txt</string>
        <void method="println">
          <string>Hello World!</string>
        </void>
        <void method="close"/>
      </object>
    </java>

The XML code above will cause the creation of a file with the content "Hello World!".

**Vulnerable Code:**

    XMLDecoder d = new XMLDecoder(in);
    try {
        Object result = d.readObject();
    }
    [...]

**Solution:**
The solution is to avoid using XMLDecoder to parse content from an untrusted source.

### References
- [Dinis Cruz Blog: Using XMLDecoder to execute server-side Java Code on a Restlet application](http://blog.diniscruz.com/2013/08/using-xmldecoder-to-execute-server-side.html)
- [RedHat blog : Java deserialization flaws: Part 2, XML deserialization](https://securityblog.redhat.com/2014/01/23/java-deserialization-flaws-part-2-xml-deserialization/)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

## Static IV[<small></small>](#STATIC_IV "Permanent link")

_<small>Bug Pattern: <tt>STATIC_IV</tt></small>_

Initialization vector must be regenerated for each message to be encrypted.

**Vulnerable Code:**

    private static byte[] IV = new byte[16] {(byte)0,(byte)1,(byte)2,[...]};

    public void encrypt(String message) throws Exception {

        IvParameterSpec ivSpec = new IvParameterSpec(IV);
    [...]

**Solution:**

    public void encrypt(String message) throws Exception {

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
    [...]

### References
- [Wikipedia: Initialization vector](https://en.wikipedia.org/wiki/Initialization_vector)
- [CWE-329: Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)
- [Encryption - CBC Mode IV: Secret or Not?](https://defuse.ca/cbcmodeiv.htm)

## ECB mode is insecure[<small></small>](#ECB_MODE "Permanent link")

_<small>Bug Pattern: <tt>ECB_MODE</tt></small>_

An authentication cipher mode which provides better confidentiality of the encrypted data should be used instead of Electronic Code Book (ECB) mode, which does not provide good confidentiality. Specifically, ECB mode produces the same output for the same input each time. So, for example, if a user is sending a password, the encrypted value is the same each time. This allows an attacker to intercept and replay the data.

To fix this, something like Galois/Counter Mode (GCM) should be used instead.

**Code at risk:**

    Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, k, iv);
    byte[] cipherText = c.doFinal(plainText);

**Solution:**

    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, k, iv);
    byte[] cipherText = c.doFinal(plainText);

### References
- [Wikipedia: Authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption)
- [NIST: Authenticated Encryption Modes](https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-develoment#01)
- [Wikipedia: Block cipher modes of operation](https://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29)
- [NIST: Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/publications/detail/sp/800-38a/final)

## Cipher is susceptible to Padding Oracle[<small></small>](#PADDING_ORACLE "Permanent link")

_<small>Bug Pattern: <tt>PADDING_ORACLE</tt></small>_

This specific mode of CBC with PKCS5Padding is susceptible to padding oracle attacks. An adversary could potentially decrypt the message if the system exposed the difference between plaintext with invalid padding or valid padding. The distinction between valid and invalid padding is usually revealed through distinct error messages being returned for each condition.

**Code at risk:**

    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.ENCRYPT_MODE, k, iv);
    byte[] cipherText = c.doFinal(plainText);

**Solution:**

    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, k, iv);
    byte[] cipherText = c.doFinal(plainText);

### References
- [Padding Oracles for the masses (by Matias Soler)](http://www.infobytesec.com/down/paddingoracle_openjam.pdf)
- [Wikipedia: Authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption)
- [NIST: Authenticated Encryption Modes](https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-develoment#01)
- [CAPEC: Padding Oracle Crypto Attack](https://capec.mitre.org/data/definitions/463.html)
- [CWE-696: Incorrect Behavior Order](https://cwe.mitre.org/data/definitions/696.html)

## Cipher with no integrity[<small></small>](#CIPHER_INTEGRITY "Permanent link")

_<small>Bug Pattern: <tt>CIPHER_INTEGRITY</tt></small>_

The ciphertext produced is susceptible to alteration by an adversary. This mean that the cipher provides no way to detect that the data has been tampered with. If the ciphertext can be controlled by an attacker, it could be altered without detection.

The solution is to use a cipher that includes a Hash based Message Authentication Code (HMAC) to sign the data. Combining a HMAC function to the existing cipher is prone to error <sup>[[1]](https://moxie.org/blog/the-cryptographic-doom-principle/)</sup>. Specifically, it is always recommended that you be able to verify the HMAC first, and only if the data is unmodified, do you then perform any cryptographic functions on the data.

The following modes are vulnerable because they don't provide a HMAC:

- CBC
- OFB
- CTR
- ECB

The following snippets code are some examples of vulnerable code.

**Code at risk:**
_AES in CBC mode_

    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.ENCRYPT_MODE, k, iv);
    byte[] cipherText = c.doFinal(plainText);

_Triple DES with ECB mode_

    Cipher c = Cipher.getInstance("DESede/ECB/PKCS5Padding");
    c.init(Cipher.ENCRYPT_MODE, k, iv);
    byte[] cipherText = c.doFinal(plainText);

**Solution:**

    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, k, iv);
    byte[] cipherText = c.doFinal(plainText);

In the example solution above, the GCM mode introduces an HMAC into the resulting encrypted data, providing integrity of the result.

### References
- [Wikipedia: Authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption)
- [NIST: Authenticated Encryption Modes](https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-develoment#01)
- [Moxie Marlinspike's blog: The Cryptographic Doom Principle](https://moxie.org/blog/the-cryptographic-doom-principle/)
- [CWE-353: Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)

## Use of ESAPI Encryptor[<small></small>](#ESAPI_ENCRYPTOR "Permanent link")

_<small>Bug Pattern: <tt>ESAPI_ENCRYPTOR</tt></small>_

The ESAPI has a small history of vulnerabilities within the cryptography component. Here is a quick validation list to make sure the Authenticated Encryption is working as expected.

**1\. Library Version**

This issue is corrected in ESAPI version 2.1.0\. Versions <= 2.0.1 are vulnerable to a MAC bypass (CVE-2013-5679).

For Maven users, the plugin [versions](https://www.mojohaus.org/versions-maven-plugin/) can be called using the following command. The effective version of ESAPI will be available in the output.

    $ mvn versions:display-dependency-updates

Output:

    [...]
    [INFO] The following dependencies in Dependencies have newer versions:
    [INFO]   org.slf4j:slf4j-api ................................... 1.6.4 -> 1.7.7
    [INFO]   org.owasp.esapi:esapi ................................. 2.0.1 -> 2.1.0
    [...]

or by looking at the configuration directly.

    <dependency>
        <groupId>org.owasp.esapi</groupId>
        <artifactId>esapi</artifactId>
        <version>2.1.0</version>
    </dependency>

For Ant users, the jar used should be [esapi-2.1.0.jar](https://repo1.maven.org/maven2/org/owasp/esapi/esapi/2.1.0/esapi-2.1.0.jar).

**2\. Configuration:**

The library version 2.1.0 is still vulnerable to key size being changed in the ciphertext definition (CVE-2013-5960). Some precautions need to be taken.

<div>**The cryptographic configuration of ESAPI can also be vulnerable if any of these elements are present:**
**Insecure configuration:**

    Encryptor.CipherText.useMAC=false

    Encryptor.EncryptionAlgorithm=AES
    Encryptor.CipherTransformation=AES/CBC/PKCS5Padding

    Encryptor.cipher_modes.additional_allowed=CBC

</div>

<div>**Secure configuration:**

    #Needed
    Encryptor.CipherText.useMAC=true

    #Needed to have a solid auth. encryption
    Encryptor.EncryptionAlgorithm=AES
    Encryptor.CipherTransformation=AES/GCM/NoPadding

    #CBC mode should be removed to avoid padding oracle
    Encryptor.cipher_modes.additional_allowed=

</div>

### References
- [ESAPI Security bulletin 1 (CVE-2013-5679)](https://github.com/peval/owasp-esapi-java/blob/master/documentation/ESAPI-security-bulletin1.pdf)
- [Vulnerability Summary for CVE-2013-5679](https://nvd.nist.gov/vuln/detail/CVE-2013-5679)
- [Synactiv: Bypassing HMAC validation in OWASP ESAPI symmetric encryption](https://www.synacktiv.com/ressources/synacktiv_owasp_esapi_hmac_bypass.pdf)
- [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)
- [ESAPI-dev mailing list: Status of CVE-2013-5960](https://lists.owasp.org/pipermail/esapi-dev/2015-March/002533)

## External file access (Android)[<small></small>](#ANDROID_EXTERNAL_FILE_ACCESS "Permanent link")

_<small>Bug Pattern: <tt>ANDROID_EXTERNAL_FILE_ACCESS</tt></small>_

The application write data to external storage (potentially SD card). There are multiple security implication to this action. First, file store on SD card will be accessible to the application having the [`READ_EXTERNAL_STORAGE`](https://developer.android.com/reference/android/Manifest.permission.html#READ_EXTERNAL_STORAGE) permission. Also, if the data persisted contains confidential information about the user, encryption would be needed.

**Code at risk:**

    file file = new File(getExternalFilesDir(TARGET_TYPE), filename);
    fos = new FileOutputStream(file);
    fos.write(confidentialData.getBytes());
    fos.flush();

**Better alternative:**

    fos = openFileOutput(filename, Context.MODE_PRIVATE);
    fos.write(string.getBytes());

### References
- [Android Official Doc: Security Tips](http://developer.android.com/training/articles/security-tips.html#ExternalStorage)
- [CERT: DRD00-J: Do not store sensitive information on external storage [...]](https://www.securecoding.cert.org/confluence/display/java/DRD00-J.+Do+not+store+sensitive-+information+on+external+storage+%28SD+card%29+unless+encrypted+first)
- [Android Official Doc: Using the External Storage](https://developer.android.com/guide/topics/data/data-storage.html#filesExternal)
- [OWASP Mobile Top 10 2014-M2: Insecure Data Storage](https://www.owasp.org/index.php/Mobile_Top_10_2014-M2)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

## Broadcast (Android)[<small></small>](#ANDROID_BROADCAST "Permanent link")

_<small>Bug Pattern: <tt>ANDROID_BROADCAST</tt></small>_

Broadcast intents can be listened by any application with the appropriate permission. It is suggested to avoid transmitting sensitive information when possible.

**Code at risk:**

    Intent i = new Intent();
    i.setAction("com.insecure.action.UserConnected");
    i.putExtra("username", user);
    i.putExtra("email", email);
    i.putExtra("session", newSessionId);

    this.sendBroadcast(v1);

**Solution (if possible):**

    Intent i = new Intent();
    i.setAction("com.secure.action.UserConnected");

    sendBroadcast(v1);

**Configuration (receiver)<sup>[1] Source: StackOverflow</sup>:**

    <manifest ...>

        <!-- Permission declaration -->
        <permission android:name="my.app.PERMISSION" />

        <receiver
            android:name="my.app.BroadcastReceiver"
            android:permission="my.app.PERMISSION"> <!-- Permission enforcement -->
            <intent-filter>
                <action android:name="com.secure.action.UserConnected" />
            </intent-filter>
        </receiver>

        ...
    </manifest>

**Configuration (sender)<sup>[1] Source: StackOverflow</sup>:**

    <manifest>
        <!-- We declare we own the permission to send broadcast to the above receiver -->
        <uses-permission android:name="my.app.PERMISSION"/>

        <!-- With the following configuration, both the sender and the receiver apps need to be signed by the same developer certificate. -->
        <permission android:name="my.app.PERMISSION" android:protectionLevel="signature"/>
    </manifest>

### References
- [CERT: DRD03-J. Do not broadcast sensitive information using an implicit intent](https://www.securecoding.cert.org/confluence/display/java/DRD03-J.+Do+not+broadcast+sensitive+information+using+an+implicit+intent)
- [Android Official Doc: BroadcastReceiver (Security)](https://developer.android.com/reference/android/content/BroadcastReceiver.html#Security)
- [Android Official Doc: Receiver configuration (see `android:permission`)](https://developer.android.com/guide/topics/manifest/receiver-element.html)
- <sup>[1]</sup> [StackOverflow: How to set permissions in broadcast sender and receiver in android](https://stackoverflow.com/a/21513368/89769)
- [CWE-925: Improper Verification of Intent by Broadcast Receiver](https://cwe.mitre.org/data/definitions/925.html)
- [CWE-927: Use of Implicit Intent for Sensitive Communication](https://cwe.mitre.org/data/definitions/927.html)

## World writable file (Android)[<small></small>](#ANDROID_WORLD_WRITABLE "Permanent link")

_<small>Bug Pattern: <tt>ANDROID_WORLD_WRITABLE</tt></small>_

The file written in this context is using the creation mode `MODE_WORLD_READABLE`. It might not be the expected behavior to expose the content being written.

**Code at risk:**

    fos = openFileOutput(filename, MODE_WORLD_READABLE);
    fos.write(userInfo.getBytes());

**Solution (using MODE_PRIVATE):**

    fos = openFileOutput(filename, MODE_PRIVATE);

**Solution (using local SQLite Database):**
Using a local SQLite database is probably the best solution to store structured data. Make sure the database file is not create on external storage. See references below for implementation guidelines.

### References
- [CERT: DRD11-J. Ensure that sensitive data is kept secure](https://www.securecoding.cert.org/confluence/display/java/DRD11-J.+Ensure+that+sensitive+data+is+kept+secure)
- [Android Official Doc: Security Tips](https://developer.android.com/training/articles/security-tips.html#InternalStorage)
- [Android Official Doc: Context.MODE_PRIVATE](https://developer.android.com/reference/android/content/Context.html#MODE_PRIVATE)
- [vogella.com: Android SQLite database and content provider - Tutorial](https://www.vogella.com/tutorials/AndroidSQLite/article.html#databasetutorial_database)
- [vogella.com: Android SQLite database and content provider - Tutorial](https://www.vogella.com/tutorials/AndroidSQLite/article.html#databasetutorial_database)
- [OWASP Mobile Top 10 2014-M2: Insecure Data Storage](https://www.owasp.org/index.php/Mobile_Top_10_2014-M2)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

## WebView with geolocation activated (Android)[<small></small>](#ANDROID_GEOLOCATION "Permanent link")

_<small>Bug Pattern: <tt>ANDROID_GEOLOCATION</tt></small>_

It is suggested to ask the user for a confirmation about obtaining its geolocation.

**Code at risk:**

    webView.setWebChromeClient(new WebChromeClient() {
        @Override
        public void onGeolocationPermissionsShowPrompt(String origin, GeolocationPermissions.Callback callback) {
            callback.invoke(origin, true, false);
        }
    });

**Suggested code:**
Limit the sampling of geolocation and ask the user for confirmation.

    webView.setWebChromeClient(new WebChromeClient() {
        @Override
        public void onGeolocationPermissionsShowPrompt(String origin, GeolocationPermissions.Callback callback) {
            callback.invoke(origin, true, false);

            //Ask the user for confirmation
        }
    });

### References
- [CERT: DRD15-J. Consider privacy concerns when using Geolocation API](https://www.securecoding.cert.org/confluence/display/java/DRD15-J.+Consider+privacy+concerns+when+using+Geolocation+API)
- [Wikipedia: W3C Geolocation API](https://en.wikipedia.org/wiki/W3C_Geolocation_API)
- [W3C: Geolocation Specification](https://w3c.github.io/geolocation-api/)

## WebView with JavaScript enabled (Android)[<small></small>](#ANDROID_WEB_VIEW_JAVASCRIPT "Permanent link")

_<small>Bug Pattern: <tt>ANDROID_WEB_VIEW_JAVASCRIPT</tt></small>_

Enabling JavaScript for the WebView means that it is now susceptible to XSS. The page render should be inspected for potential reflected XSS, stored XSS and DOM XSS.

    WebView myWebView = (WebView) findViewById(R.id.webView);
    WebSettings webSettings = myWebView.getSettings();
    webSettings.setJavaScriptEnabled(true);

**Code at risk:**
Enabling JavaScript is not a bad practice. It just means that the backend code need to be audited for potential XSS. The XSS can also be introduced client-side with DOM XSS.

    function updateDescription(newDescription) {
        $("#userDescription").html("<p>"+newDescription+"</p>");
    }

### References
- [Issue: Using `setJavaScriptEnabled` can introduce XSS vulnerabilities](http://www.technotalkative.com/issue-using-setjavascriptenabled-can-introduce-xss-vulnerabilities-application-review-carefully/)
- [Android Official Doc: WebView](https://developer.android.com/guide/webapps/webview.html#UsingJavaScript)
- [WASC-8: Cross Site Scripting](http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting)
- [OWASP: XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet)
- [OWASP: Top 10 2013-A3: Cross-Site Scripting (XSS)](https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_%28XSS%29)
- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

## WebView with JavaScript interface (Android)[<small></small>](#ANDROID_WEB_VIEW_JAVASCRIPT_INTERFACE "Permanent link")

_<small>Bug Pattern: <tt>ANDROID_WEB_VIEW_JAVASCRIPT_INTERFACE</tt></small>_

The use of JavaScript Interface could expose the WebView to risky API. If an XSS is triggered in the WebView, the class could be called by the malicious JavaScript code.

**Code at risk:**

    WebView myWebView = (WebView) findViewById(R.id.webView);

    myWebView.addJavascriptInterface(new FileWriteUtil(this), "fileWriteUtil");

    WebSettings webSettings = myWebView.getSettings();
    webSettings.setJavaScriptEnabled(true);

    [...]
    class FileWriteUtil {
        Context mContext;

        FileOpenUtil(Context c) {
            mContext = c;
        }

        public void writeToFile(String data, String filename, String tag) {
            [...]
        }
    }

### References
- [Android Official Doc: `WebView.addJavascriptInterface()`](https://developer.android.com/reference/android/webkit/WebView.html#addJavascriptInterface%28java.lang.Object,%20java.lang.String%29)
- [CWE-749: Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)

## Cookie without the secure flag[<small></small>](#INSECURE_COOKIE "Permanent link")

_<small>Bug Pattern: <tt>INSECURE_COOKIE</tt></small>_

A new cookie is created without the `Secure` flag set. The `Secure` flag is a directive to the browser to make sure that the cookie is not sent for insecure communication (`http://`).

**Code at risk:**

    Cookie cookie = new Cookie("userName",userName);
    response.addCookie(cookie);

**Solution (Specific configuration):**

    Cookie cookie = new Cookie("userName",userName);
    cookie.setSecure(true); // Secure flag
    cookie.setHttpOnly(true);

**Solution (Servlet 3.0 configuration):**

    <web-app xmlns="http://java.sun.com/xml/ns/javaee" version="3.0">
    [...]
    <session-config>
     <cookie-config>
      <http-only>true</http-only>
      <secure>true</secure>
     </cookie-config>
    </session-config>
    </web-app>

### References
- [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)
- [CWE-315: Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
- [OWASP: Secure Flag](https://www.owasp.org/index.php/SecureFlag)
- [Rapid7: Missing Secure Flag From SSL Cookie](https://www.rapid7.com/db/vulnerabilities/http-cookie-secure-flag)

## Cookie without the HttpOnly flag[<small></small>](#HTTPONLY_COOKIE "Permanent link")

_<small>Bug Pattern: <tt>HTTPONLY_COOKIE</tt></small>_

A new cookie is created without the `HttpOnly` flag set. The `HttpOnly` flag is a directive to the browser to make sure that the cookie can not be red by malicious script. When a user is the target of a "Cross-Site Scripting", the attacker would benefit greatly from getting the session id for example.

**Code at risk:**

    Cookie cookie = new Cookie("email",userName);
    response.addCookie(cookie);

**Solution (Specific configuration):**

    Cookie cookie = new Cookie("email",userName);
    cookie.setSecure(true);
    cookie.setHttpOnly(true); //HttpOnly flag

**Solution (Servlet 3.0 configuration):**

    <web-app xmlns="http://java.sun.com/xml/ns/javaee" version="3.0">
    [...]
    <session-config>
     <cookie-config>
      <http-only>true</http-only>
      <secure>true</secure>
     </cookie-config>
    </session-config>
    </web-app>

### References
- [Coding Horror blog: Protecting Your Cookies: HttpOnly](https://blog.codinghorror.com/protecting-your-cookies-httponly/)
- [OWASP: HttpOnly](https://www.owasp.org/index.php/HttpOnly)
- [Rapid7: Missing HttpOnly Flag From Cookie](https://www.rapid7.com/db/vulnerabilities/http-cookie-http-only-flag)

## Object deserialization is used[<small></small>](#OBJECT_DESERIALIZATION "Permanent link")

_<small>Bug Pattern: <tt>OBJECT_DESERIALIZATION</tt></small>_

Object deserialization of untrusted data can lead to remote code execution, if there is a class in classpath that allows the trigger of malicious operation.

Libraries developers tend to fix class that provided potential malicious trigger. There are still classes that are known to trigger Denial of Service<sup>[1]</sup>.

Deserialization is a sensible operation that has a great history of vulnerabilities. The web application might become vulnerable as soon as a new vulnerability is found in the Java Virtual Machine<sup>[2][3]</sup>.

**Code at risk:**

    public UserData deserializeObject(InputStream receivedFile) throws IOException, ClassNotFoundException {

        try (ObjectInputStream in = new ObjectInputStream(receivedFile)) {
            return (UserData) in.readObject();
        }
    }

**Solutions:**

Avoid deserializing object provided by remote users.

### References
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Deserialization of untrusted data](https://www.owasp.org/index.php/Deserialization_of_untrusted_data)
- [Serialization and Deserialization](https://www.oracle.com/technetwork/java/seccodeguide-139067.html#8)
- [A tool for generating payloads that exploit unsafe Java object deserialization](https://github.com/frohoff/ysoserial)
- [1][example of denial of service using the class `java.util.hashset`](https://gist.github.com/coekie/a27cc406fc9f3dc7a70d)
- [2][openjdk: deserialization issue in objectinputstream.readserialdata() (cve-2015-2590)](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2015-2590)
- [3][rapid7: sun java calendar deserialization privilege escalation (cve-2008-5353)](https://www.rapid7.com/db/modules/exploit/multi/browser/java_calendar_deserialize)

## Unsafe Jackson deserialization configuration[<small></small>](#JACKSON_UNSAFE_DESERIALIZATION "Permanent link")

_<small>Bug Pattern: <tt>JACKSON_UNSAFE_DESERIALIZATION</tt></small>_

When the Jackson databind library is used incorrectly the deserialization of untrusted data can lead to remote code execution, if there is a class in classpath that allows the trigger of malicious operation.

**Solutions:**

Explicitly define what types and subtypes you want to be available when using polymorphism through JsonTypeInfo.Id.NAME. Also, never call `ObjectMapper.enableDefaultTyping` (and then `readValue` a type that holds a Object or Serializable or Comparable or a known deserialization type).

**Code at risk:**

    public class Example {
        static class ABean {
            public int id;
            public Object obj;
        }

        static class AnotherBean {
            @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS) // or JsonTypeInfo.Id.MINIMAL_CLASS
            public Object obj;
        }

        public void example(String json) throws JsonMappingException {
             ObjectMapper mapper = new ObjectMapper();
             mapper.enableDefaultTyping();
             mapper.readValue(json, ABean.class);
        }

        public void exampleTwo(String json) throws JsonMappingException {
             ObjectMapper mapper = new ObjectMapper();
             mapper.readValue(json, AnotherBean.class);
        }

    }

### References
- [Jackson Deserializer security vulnerability](https://github.com/FasterXML/jackson-databind/issues/1599)
- [Java Unmarshaller Security - Turning your data into code execution](https://github.com/mbechler/marshalsec)

## This class could be used as deserialization gadget[<small></small>](#DESERIALIZATION_GADGET "Permanent link")

_<small>Bug Pattern: <tt>DESERIALIZATION_GADGET</tt></small>_

Deserialization gadget are class that could be used by an attacker to take advantage of a remote API using Native Serialization. This class is either adding custom behavior to deserialization with the `readObject` method (Serializable) or can be called from a serialized object (InvocationHandler).

This detector is intended to be used mostly by researcher. The real issue is using deserialization for remote operation. Removing gadget is a hardening practice to reduce the risk of being exploited.

### References
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Deserialization of untrusted data](https://www.owasp.org/index.php/Deserialization_of_untrusted_data)
- [Serialization and Deserialization](https://www.oracle.com/technetwork/java/seccodeguide-139067.html#8)
- [A tool for generating payloads that exploit unsafe Java object deserialization](https://github.com/frohoff/ysoserial)
- [1][example of denial of service using the class `java.util.hashset`](https://gist.github.com/coekie/a27cc406fc9f3dc7a70d)
- [2][openjdk: deserialization issue in objectinputstream.readserialdata() (cve-2015-2590)](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2015-2590)
- [3][rapid7: sun java calendar deserialization privilege escalation (cve-2008-5353)](https://www.rapid7.com/db/modules/exploit/multi/browser/java_calendar_deserialize)

## Trust Boundary Violation[<small></small>](#TRUST_BOUNDARY_VIOLATION "Permanent link")

_<small>Bug Pattern: <tt>TRUST_BOUNDARY_VIOLATION</tt></small>_

"A trust boundary can be thought of as line drawn through a program. On one side of the line, data is untrusted. On the other side of the line, data is assumed to be trustworthy. The purpose of validation logic is to allow data to safely cross the trust boundary - to move from untrusted to trusted. A trust boundary violation occurs when a program blurs the line between what is trusted and what is untrusted. By combining trusted and untrusted data in the same data structure, it becomes easier for programmers to mistakenly trust unvalidated data." <sup>[1]</sup>

**Code at risk:**

    public void doSomething(HttpServletRequest req, String activateProperty) {
        //..

        req.getSession().setAttribute(activateProperty,"true");

    }

    public void loginEvent(HttpServletRequest req, String userSubmitted) {
        //..

        req.getSession().setAttribute("user",userSubmitted);
    }

**Solution:**

The solution would be to add validation prior setting a new session attribute. When possible, prefer data from safe location rather than using direct user input.

### References
- [1][cwe-501: trust boundary violation](https://cwe.mitre.org/data/definitions/501.html)
- [OWASP : Trust Boundary Violation](https://www.owasp.org/index.php/Trust_Boundary_Violation)

## A malicious XSLT could be provided to the JSP tag[<small></small>](#JSP_XSLT "Permanent link")

_<small>Bug Pattern: <tt>JSP_XSLT</tt></small>_

"XSLT (Extensible Stylesheet Language Transformations) is a language for transforming XML documents into other XML documents".<sup>[1]</sup>
It is possible to attach malicious behavior to those style sheets. Therefore, if an attacker can control the content or the source of the style sheet, he might be able to trigger remote code execution.<sup>[2]</sup>

**Code at risk:**

    <x:transform xml="${xmlData}" xslt="${xsltControlledByUser}" />

**Solution:**

The solution would be to make sure the style sheet is loaded from a safe sources and make sure that vulnerabilities such as Path traversal <sup>[3][4]</sup> are not possible.

### References
- [1][wikipedia: xslt (extensible stylesheet language transformations)](https://en.wikipedia.org/wiki/XSLT)
- [Offensive XSLT](https://prezi.com/y_fuybfudgnd/offensive-xslt/) by Nicolas Grégoire
- [2][from xslt code execution to meterpreter shells](https://www.agarri.fr/blog/archives/2012/07/02/from_xslt_code_execution_to_meterpreter_shells/index.html) by Nicolas - Grégoire
- [XSLT Hacking Encyclopedia](https://xhe.myxwiki.org/xwiki/bin/view/Main/) by Nicolas Grégoire
- [Acunetix.com : The hidden dangers of XSLTProcessor - Remote XSL injection](https://www.acunetix.com/blog/articles/the-hidden-dangers-of-xsltprocessor-remote-xsl-injection/)
- [w3.org XSL Transformations (XSLT) Version 1.0](https://www.w3.org/TR/xslt) : w3c specification
- [3][wasc: path traversal](http://projects.webappsec.org/w/page/13246952/Path%20Traversal)
- [4][owasp: path traversal](https://www.owasp.org/index.php/Path_Traversal)

## A malicious XSLT could be provided[<small></small>](#MALICIOUS_XSLT "Permanent link")

_<small>Bug Pattern: <tt>MALICIOUS_XSLT</tt></small>_

"XSLT (Extensible Stylesheet Language Transformations) is a language for transforming XML documents into other XML documents".<sup>[1]</sup>
It is possible to attach malicious behavior to those style sheets. Therefore, if an attacker can control the content or the source of the style sheet, he might be able to trigger remote code execution.<sup>[2]</sup>

**Code at risk:**

    Source xslt = new StreamSource(new FileInputStream(inputUserFile)); //Dangerous source

    Transformer transformer = TransformerFactory.newInstance().newTransformer(xslt);

    Source text = new StreamSource(new FileInputStream("/data_2_process.xml"));
    transformer.transform(text, new StreamResult(...));

**Solution:**

The solution is to enable the secure processing mode which will block potential reference to Java classes such as `java.lang.Runtime`.

    TransformerFactory factory = TransformerFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    Source xslt  = new StreamSource(new FileInputStream(inputUserFile));

    Transformer transformer = factory.newTransformer(xslt);

Alternatively, make sure the style sheet is loaded from a safe sources and make sure that vulnerabilities such as Path traversal <sup>[3][4]</sup> are not possible.

### References
- [1][wikipedia: xslt (extensible stylesheet language transformations)](https://en.wikipedia.org/wiki/XSLT)
- [Offensive XSLT](https://prezi.com/y_fuybfudgnd/offensive-xslt/) by Nicolas Grégoire
- [2][from xslt code execution to meterpreter shells](https://www.agarri.fr/blog/archives/2012/07/02/from_xslt_code_execution_to_meterpreter_shells/index.html) by Nicolas - Grégoire
- [XSLT Hacking Encyclopedia](https://xhe.myxwiki.org/xwiki/bin/view/Main/) by Nicolas Grégoire
- [Acunetix.com : The hidden dangers of XSLTProcessor - Remote XSL injection](https://www.acunetix.com/blog/articles/the-hidden-dangers-of-xsltprocessor-remote-xsl-injection/)
- [w3.org XSL Transformations (XSLT) Version 1.0](https://www.w3.org/TR/xslt) : w3c specification
- [3][wasc: path traversal](http://projects.webappsec.org/w/page/13246952/Path%20Traversal)
- [4][owasp: path traversal](https://www.owasp.org/index.php/Path_Traversal)

## Potential information leakage in Scala Play[<small></small>](#SCALA_SENSITIVE_DATA_EXPOSURE "Permanent link")

_<small>Bug Pattern: <tt>SCALA_SENSITIVE_DATA_EXPOSURE</tt></small>_

Applications can unintentionally leak information about their configuration, internal workings, or violate privacy through a variety of application problems. <sup>[1]</sup> Pages that provide different responses based on the validity of the data can lead to Information Leakage; specifically when data deemed confidential is being revealed as a result of the web application's design. <sup>[2]</sup>

Examples of sensitive data includes (but is not limited to): API keys, passwords, product versions or environment configurations.

**Code at risk:**

    def doGet(value:String) = Action {
      val configElement = configuration.underlying.getString(value)

      Ok("Hello "+ configElement +" !")
    }

Application configuration elements should not be sent in the response content and users should not be allowed to control which configuration elements will be used by the code.

### References
- [OWASP: Top 10 2013-A6-Sensitive Data Exposure](https://www.owasp.org/index.php/Top_10_2013-A6-Sensitive_Data_Exposure)
- [1][owasp: top 10 2007-information leakage and improper error handling](https://www.owasp.org/index.php/Top_10_2007-Information_Leakage_and_Improper_Error_Handling)
- [2][wasc-13: information leakage](http://projects.webappsec.org/w/page/13246936/Information%20Leakage)
- [CWE-200: Information Exposure](https://cwe.mitre.org/data/definitions/200.html)

## Scala Play Server-Side Request Forgery (SSRF)[<small></small>](#SCALA_PLAY_SSRF "Permanent link")

_<small>Bug Pattern: <tt>SCALA_PLAY_SSRF</tt></small>_

Server-Side Request Forgery occur when a web server executes a request to a user supplied destination parameter that is not validated. Such vulnerabilities could allow an attacker to access internal services or to launch attacks from your web server.

**Vulnerable Code:**

    def doGet(value:String) = Action {
        WS.url(value).get().map { response =>
            Ok(response.body)
        }
    }

**Solution/Countermeasures:**

- Don't accept request destinations from users
- Accept a destination key, and use it to look up the target (legal) destination
- White list URLs (if possible)
- Validate that the beginning of the URL is part of a white list

### References
[CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
[Understanding Server-Side Request Forgery](https://www.bishopfox.com/blog/2015/04/vulnerable-by-design-understanding-server-side-request-forgery/)

## URLConnection Server-Side Request Forgery (SSRF) and File Disclosure[<small></small>](#URLCONNECTION_SSRF_FD "Permanent link")

_<small>Bug Pattern: <tt>URLCONNECTION_SSRF_FD</tt></small>_

Server-Side Request Forgery occur when a web server executes a request to a user supplied destination parameter that is not validated. Such vulnerabilities could allow an attacker to access internal services or to launch attacks from your web server.

URLConnection can be used with file:// protocol or other protocols to access local filesystem and potentially other services.

**Vulnerable Code:**

    new URL(String url).openConnection()

    new URL(String url).openStream()

    new URL(String url).getContent()

**Solution/Countermeasures:**

- Don't accept URL destinations from users
- Accept a destination key, and use it to look up the target destination associate with the key
- White list URLs (if possible)
- Validate that the beginning of the URL is part of a white list

### References
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [Understanding Server-Side Request Forgery](https://www.bishopfox.com/blog/2015/04/vulnerable-by-design-understanding-server-side-request-forgery/)
- [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
- [Abusing jar:// downloads](https://www.pwntester.com/blog/2013/11/28/abusing-jar-downloads/)

## Potential XSS in Scala Twirl template engine[<small></small>](#SCALA_XSS_TWIRL "Permanent link")

_<small>Bug Pattern: <tt>SCALA_XSS_TWIRL</tt></small>_

A potential XSS was found. It could be used to execute unwanted JavaScript in a client's browser. (See references)

**Vulnerable Code:**

    @(value: Html)

    @value

**Solution:**

    @(value: String)

    @value

The best defense against XSS is context sensitive output encoding like the example above. There are typically 4 contexts to consider: HTML, JavaScript, CSS (styles), and URLs. Please follow the XSS protection rules defined in the OWASP XSS Prevention Cheat Sheet, which explains these defenses in significant detail.

### References
- [WASC-8: Cross Site Scripting](http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting)
- [OWASP: XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet)
- [OWASP: Top 10 2013-A3: Cross-Site Scripting (XSS)](https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_%28XSS%29)
- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Java Encoder](https://code.google.com/p/owasp-java-encoder/)

## Potential XSS in Scala MVC API engine[<small></small>](#SCALA_XSS_MVC_API "Permanent link")

_<small>Bug Pattern: <tt>SCALA_XSS_MVC_API</tt></small>_

A potential XSS was found. It could be used to execute unwanted JavaScript in a client's browser. (See references)

**Vulnerable Code:**

    def doGet(value:String) = Action {
        Ok("Hello " + value + " !").as("text/html")
      }

**Solution:**

    def doGet(value:String) = Action {
        Ok("Hello " + Encode.forHtml(value) + " !")
      }

The best defense against XSS is context sensitive output encoding like the example above. There are typically 4 contexts to consider: HTML, JavaScript, CSS (styles), and URLs. Please follow the XSS protection rules defined in the OWASP XSS Prevention Cheat Sheet, which explains these defenses in significant detail.

### References
- [WASC-8: Cross Site Scripting](http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting)
- [OWASP: XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet)
- [OWASP: Top 10 2013-A3: Cross-Site Scripting (XSS)](https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_%28XSS%29)
- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Java Encoder](https://code.google.com/p/owasp-java-encoder/)

## Potential template injection with Velocity[<small></small>](#TEMPLATE_INJECTION_VELOCITY "Permanent link")

_<small>Bug Pattern: <tt>TEMPLATE_INJECTION_VELOCITY</tt></small>_

Velocity template engine is powerful. It is possible to add logic including condition statements, loops and external calls. It is not design to be sandbox to templating operations. A malicious user in control of a template can run malicious code on the server-side. Velocity templates should be seen as scripts.

**Vulnerable Code:**

    [...]

    Velocity.evaluate(context, swOut, "test", userInput);

**Solution:**
Avoid letting end users manipulate templates with Velocity. If you need to expose template editing to your users, prefer logic-less template engines such as Handlebars or Moustache (See references).

### References
- [PortSwigger: Server-Side Template Injection](https://blog.portswigger.net/2015/08/server-side-template-injection.html)
- [Handlebars.java](https://jknack.github.io/handlebars.java/)

## Potential template injection with Freemarker[<small></small>](#TEMPLATE_INJECTION_FREEMARKER "Permanent link")

_<small>Bug Pattern: <tt>TEMPLATE_INJECTION_FREEMARKER</tt></small>_

Freemarker template engine is powerful. It is possible to add logic including condition statements, loops and external calls. It is not design to be sandbox to templating operations. A malicious user in control of a template can run malicious code on the server-side. Freemarker templates should be seen as scripts.

**Vulnerable Code:**

    Template template = cfg.getTemplate(inputTemplate);
    [...]
    template.process(data, swOut);

**Solution:**
Avoid letting end users manipulate templates with Freemarker. If you need to expose template editing to your users, prefer logic-less template engines such as Handlebars or Moustache (See references).

### References
- [PortSwigger: Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)
- [Handlebars.java](https://jknack.github.io/handlebars.java/)

## Potential template injection with Pebble[<small></small>](#TEMPLATE_INJECTION_PEBBLE "Permanent link")

_<small>Bug Pattern: <tt>TEMPLATE_INJECTION_PEBBLE</tt></small>_

Freemarker template engine is powerful. It is possible to add logic including condition statements, loops and external calls. It is not design to be sandbox to templating operations. A malicious user in control of a template can run malicious code on the server-side. Freemarker templates should be seen as scripts.

**Vulnerable Code:**

    PebbleTemplate compiledTemplate = engine.getLiteralTemplate(inputFile);
    [...]
    compiledTemplate.evaluate(writer, context);

**Solution:**
Avoid letting end users manipulate templates with Pebble. If you need to expose template editing to your users, prefer logic-less template engines such as Handlebars or Moustache (See references).

### References
- [PortSwigger: Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)
- [Handlebars.java](https://jknack.github.io/handlebars.java/)

## Overly permissive CORS policy[<small></small>](#PERMISSIVE_CORS "Permanent link")

_<small>Bug Pattern: <tt>PERMISSIVE_CORS</tt></small>_

Prior to HTML5, Web browsers enforced the Same Origin Policy which ensures that in order for JavaScript to access the contents of a Web page, both the JavaScript and the Web page must originate from the same domain. Without the Same Origin Policy, a malicious website could serve up JavaScript that loads sensitive information from other websites using a client's credentials, cull through it, and communicate it back to the attacker. HTML5 makes it possible for JavaScript to access data across domains if a new HTTP header called Access-Control-Allow-Origin is defined. With this header, a Web server defines which other domains are allowed to access its domain using cross-origin requests. However, caution should be taken when defining the header because an overly permissive CORS policy will allow a malicious application to communicate with the victim application in an inappropriate way, leading to spoofing, data theft, relay and other attacks.

**Vulnerable Code:**

    response.addHeader("Access-Control-Allow-Origin", "*");

**Solution:**
Avoid using \* as the value of the Access-Control-Allow-Origin header, which indicates that the application's data is accessible to JavaScript running on any domain.

### References
- [W3C Cross-Origin Resource Sharing](https://www.w3.org/TR/cors/)
- [Enable Cross-Origin Resource Sharing](https://enable-cors.org/)

## Anonymous LDAP bind[<small></small>](#LDAP_ANONYMOUS "Permanent link")

_<small>Bug Pattern: <tt>LDAP_ANONYMOUS</tt></small>_

Without proper access control, executing an LDAP statement that contains a user-controlled value can allow an attacker to abuse poorly configured LDAP context. All LDAP queries executed against the context will be performed without authentication and access control. An attacker may be able to manipulate one of these queries in an unexpected way to gain access to records that would otherwise be protected by the directory's access control mechanism.

**Vulnerable Code:**

    ...
    env.put(Context.SECURITY_AUTHENTICATION, "none");
    DirContext ctx = new InitialDirContext(env);
    ...

**Solution:**
Consider other modes of authentication to LDAP and ensure proper access control mechanism.

### References
- [Ldap Authentication Mechanisms](https://docs.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html)

## LDAP Entry Poisoning[<small></small>](#LDAP_ENTRY_POISONING "Permanent link")

_<small>Bug Pattern: <tt>LDAP_ENTRY_POISONING</tt></small>_

JNDI API support the binding of serialize object in LDAP directories. If certain attributes are presented, the deserialization of object will be made in the application querying the directory (See Black Hat USA 2016 white paper for details). Object deserialization should be consider a risky operation that can lead to remote code execution.

The exploitation of the vulnerability will be possible if the attacker has an entry point in an LDAP base query, by adding attributes to an existing LDAP entry or by configuring the application to use a malicious LDAP server.

**Vulnerable Code:**

    DirContext ctx = new InitialDirContext();
    //[...]

    ctx.search(query, filter,
            new SearchControls(scope, countLimit, timeLimit, attributes,
                true, //Enable object deserialization if bound in directory
                deref));

**Solution:**

    DirContext ctx = new InitialDirContext();
    //[...]

    ctx.search(query, filter,
            new SearchControls(scope, countLimit, timeLimit, attributes,
                false, //Disable
                deref));

### References
- [Black Hat USA 2016: A Journey From JNDI/LDAP Manipulation to Remote Code Execution Dream Land](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf) ([slides](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf) & [video](https://www.youtube.com/watch?v=Y8a5nB-vy78)) by Alvaro Muñoz and Oleksandr Mirosh
- [HP Enterprise: Introducing JNDI Injection and LDAP Entry Poisoning](https://community.hpe.com/t5/Security-Research/Introducing-JNDI-Injection-and-LDAP-Entry-Poisoning/ba-p/6885118) by Alvaro Muñoz
- [TrendMicro: How The Pawn Storm Zero-Day Evaded Java's Click-to-Play Protection](http://blog.trendmicro.com/trendlabs-security-intelligence/new-headaches-how-the-pawn-storm-zero-day-evaded-javas-click-to-play-protection/) by Jack Tang

## Persistent Cookie Usage[<small></small>](#COOKIE_PERSISTENT "Permanent link")

_<small>Bug Pattern: <tt>COOKIE_PERSISTENT</tt></small>_

Storing sensitive data in a persistent cookie for an extended period can lead to a breach of confidentiality or account compromise.

**Explanation:**
If private information is stored in persistent cookies, attackers have a larger time window in which to steal this data - especially since persistent cookies are often set to expire in the distant future. Persistent cookies are generally stored in a text file on the client and an attacker with access to the victim's machine can steal this information.
Persistent cookies are often used to profile users as they interact with a site. Depending on what is done with this tracking data, it is possible to use persistent cookies to violate users' privacy.

**Vulnerable Code:** The following code sets a cookie to expire in 1 year.

    [...]
    Cookie cookie = new Cookie("email", email);
    cookie.setMaxAge(60*60*24*365);
    [...]

**Solution:**

- Use persistent cookies only if necessary and limit their maximum age.
- Don't use persistent cookies for sensitive data.

### References
- [Class Cookie `setMaxAge` documentation](https://tomcat.apache.org/tomcat-5.5-doc/servletapi/javax/servlet/http/Cookie.html#setMaxAge%28int%29)
- [CWE-539: Information Exposure Through Persistent Cookies](https://cwe.mitre.org/data/definitions/539.html)

## URL rewriting method[<small></small>](#URL_REWRITING "Permanent link")

_<small>Bug Pattern: <tt>URL_REWRITING</tt></small>_

The implementation of this method includes the logic to determine whether the session ID needs to be encoded in the URL.
URL rewriting has significant security risks. Since session ID appears in the URL, it may be easily seen by third parties. Session ID in the URL can be disclosed in many ways, for example:

- Log files,
- The browser history,
- By copy-and-pasting it into an e-mail or posting,
- The HTTP Referrer.

**Vulnerable Code:**

    out.println("Click <a href=" +
                    res.encodeURL(HttpUtils.getRequestURL(req).toString()) +
                    ">here</a>");

**Solution:**
Avoid using those methods. If you are looking to encode a URL String or form parameters do not confuse the URL rewriting methods with the URLEncoder class.

### References
- [OWASP Top 10 2010-A3-Broken Authentication and Session Management](https://www.owasp.org/index.php/Top_10_2010-A3-Broken_Authentication_and_Session_Management)

## Insecure SMTP SSL connection[<small></small>](#INSECURE_SMTP_SSL "Permanent link")

_<small>Bug Pattern: <tt>INSECURE_SMTP_SSL</tt></small>_

Server identity verification is disabled when making SSL connections. Some email libraries that enable SSL connections do not verify the server certificate by default. This is equivalent to trusting all certificates. When trying to connect to the server, this application would readily accept a certificate issued to "victim.com". The application would now potentially leak sensitive user information on a broken SSL connection to the victim server.

**Vulnerable Code:**

    ...
    Email email = new SimpleEmail();
    email.setHostName("smtp.servermail.com");
    email.setSmtpPort(465);
    email.setAuthenticator(new DefaultAuthenticator(username, password));
    email.setSSLOnConnect(true);
    email.setFrom("user@gmail.com");
    email.setSubject("TestMail");
    email.setMsg("This is a test mail ... :-)");
    email.addTo("foo@bar.com");
    email.send();
    ...

**Solution:**
Please add the following check to verify the server certificate:

    email.setSSLCheckServerIdentity(true);

### References
- [CWE-297: Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

## AWS Query Injection[<small></small>](#AWS_QUERY_INJECTION "Permanent link")

_<small>Bug Pattern: <tt>AWS_QUERY_INJECTION</tt></small>_

Constructing SimpleDB queries containing user input can allow an attacker to view unauthorized records.
The following example dynamically constructs and executes a SimpleDB SELECT query allowing the user to specify the productCategory. The attacker can modify the query, bypass the required authentication for customerID and view records matching any customer.

**Vulnerable Code:**

    ...
    String customerID = getAuthenticatedCustomerID(customerName, customerCredentials);
    String productCategory = request.getParameter("productCategory");
    ...
    AmazonSimpleDBClient sdbc = new AmazonSimpleDBClient(appAWSCredentials);
    String query = "select * from invoices where productCategory = '"
                + productCategory + "' and customerID = '"
                + customerID + "' order by '"
                + sortColumn + "' asc";
    SelectResult sdbResult = sdbc.select(new SelectRequest(query));

**Solution:**
This issue is analogical to SQL Injection. Sanitize user input before using it in a SimpleDB query.

### References
- [CWE-943: Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)

## JavaBeans Property Injection[<small></small>](#BEAN_PROPERTY_INJECTION "Permanent link")

_<small>Bug Pattern: <tt>BEAN_PROPERTY_INJECTION</tt></small>_

An attacker can set arbitrary bean properties that can compromise system integrity. Bean population functions allow to set a bean property or a nested property. An attacker can leverage this functionality to access special bean properties like `class.classLoader` that will allow him to override system properties and potentially execute arbitrary code.

**Vulnerable Code:**

    MyBean bean = ...;
    HashMap map = new HashMap();
    Enumeration names = request.getParameterNames();
    while (names.hasMoreElements()) {
        String name = (String) names.nextElement();
        map.put(name, request.getParameterValues(name));
    }
    BeanUtils.populate(bean, map);

**Solution:**
Avoid using user controlled values to populate Bean property names.

### References
- [CWE-15: External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

## Struts File Disclosure[<small></small>](#STRUTS_FILE_DISCLOSURE "Permanent link")

_<small>Bug Pattern: <tt>STRUTS_FILE_DISCLOSURE</tt></small>_

Constructing a server-side redirect path with user input could allow an attacker to download application binaries (including application classes or jar files) or view arbitrary files within protected directories.
An attacker may be able to forge a request parameter to match sensitive file locations. For example, requesting `"http://example.com/?returnURL=WEB-INF/applicationContext.xml"` would display the application's `applicationContext.xml` file. The attacker would be able to locate and download the `applicationContext.xml` referenced in the other configuration files, and even class files or jar files, obtaining sensitive information and launching other types of attacks.

**Vulnerable Code:**

    ...
    String returnURL = request.getParameter("returnURL");
    Return new ActionForward(returnURL);
    ...

**Solution:**
Avoid constructing server-side redirects using user controlled input.

### References
- [CWE-552: Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

## Spring File Disclosure[<small></small>](#SPRING_FILE_DISCLOSURE "Permanent link")

_<small>Bug Pattern: <tt>SPRING_FILE_DISCLOSURE</tt></small>_

Constructing a server-side redirect path with user input could allow an attacker to download application binaries (including application classes or jar files) or view arbitrary files within protected directories.
An attacker may be able to forge a request parameter to match sensitive file locations. For example, requesting `"http://example.com/?returnURL=WEB-INF/applicationContext.xml"` would display the application's `applicationContext.xml` file. The attacker would be able to locate and download the `applicationContext.xml` referenced in the other configuration files, and even class files or jar files, obtaining sensitive information and launching other types of attacks.

**Vulnerable Code:**

    ...
    String returnURL = request.getParameter("returnURL");
    return new ModelAndView(returnURL);
    ...

**Solution:**
Avoid constructing server-side redirects using user controlled input.

### References
- [CWE-552: Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

## RequestDispatcher File Disclosure[<small></small>](#REQUESTDISPATCHER_FILE_DISCLOSURE "Permanent link")

_<small>Bug Pattern: <tt>REQUESTDISPATCHER_FILE_DISCLOSURE</tt></small>_

Constructing a server-side redirect path with user input could allow an attacker to download application binaries (including application classes or jar files) or view arbitrary files within protected directories.
An attacker may be able to forge a request parameter to match sensitive file locations. For example, requesting `"http://example.com/?jspFile=../applicationContext.xml%3F"` would display the application's `applicationContext.xml` file. The attacker would be able to locate and download the `applicationContext.xml` referenced in the other configuration files, and even class files or jar files, obtaining sensitive information and launching other types of attacks.

**Vulnerable Code:**

    ...
    String jspFile = request.getParameter("jspFile");
    request.getRequestDispatcher("/WEB-INF/jsps/" + jspFile + ".jsp").include(request, response);
    ...

**Solution:**
Avoid constructing server-side redirects using user controlled input.

### References
- [CWE-552: Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

## Format String Manipulation[<small></small>](#FORMAT_STRING_MANIPULATION "Permanent link")

_<small>Bug Pattern: <tt>FORMAT_STRING_MANIPULATION</tt></small>_

Allowing user input to control format parameters could enable an attacker to cause exceptions to be thrown or leak information.
Attackers may be able to modify the format string argument, such that an exception is thrown. If this exception is left uncaught, it may crash the application. Alternatively, if sensitive information is used within the unused arguments, attackers may change the format string to reveal this information.
The example code below lets the user specify the decimal points to which it shows the balance. The user can in fact specify anything causing an exception to be thrown which could lead to application failure. Even more critical within this example, if an attacker can specify the user input `"2f %3$s %4$.2"`, the format string would be `"The customer: %s %s has the balance %4$.2f %3$s %4$.2"`. This would then lead to the sensitive `accountNo` to be included within the resulting string.

**Vulnerable Code:**

    Formatter formatter = new Formatter(Locale.US);
    String format = "The customer: %s %s has the balance %4$." + userInput + "f";
    formatter.format(format, firstName, lastName, accountNo, balance);

**Solution:**
Avoid using user controlled values in the format string argument.

### References
- [CWE-134: Use of Externally-Controlled Format String](https://cwe.mitre.org/data/definitions/134.html)

## HTTP Parameter Pollution[<small></small>](#HTTP_PARAMETER_POLLUTION "Permanent link")

_<small>Bug Pattern: <tt>HTTP_PARAMETER_POLLUTION</tt></small>_

Concatenating unvalidated user input into a URL can allow an attacker to override the value of a request parameter. Attacker may be able to override existing parameter values, inject a new parameter or exploit variables out of a direct reach. HTTP Parameter Pollution (HPP) attacks consist of injecting encoded query string delimiters into other existing parameters. If a web application does not properly sanitize the user input, a malicious user may compromise the logic of the application to perform either client-side or server-side attacks.
In the following example the programmer has not considered the possibility that an attacker could provide a parameter `lang` such as `en&user_id=1`, which would enable him to change the `user_id` at will.

**Vulnerable Code:**

    String lang = request.getParameter("lang");
    GetMethod get = new GetMethod("http://www.host.com");
    get.setQueryString("lang=" + lang + "&user_id=" + user_id);
    get.execute();

**Solution:**
Sanitize user input before using it in HTTP parameters.

### References
- [CAPEC-460: HTTP Parameter Pollution (HPP)](https://capec.mitre.org/data/definitions/460.html)

## Information Exposure Through An Error Message[<small></small>](#INFORMATION_EXPOSURE_THROUGH_AN_ERROR_MESSAGE "Permanent link")

_<small>Bug Pattern: <tt>INFORMATION_EXPOSURE_THROUGH_AN_ERROR_MESSAGE</tt></small>_

The sensitive information may be valuable information on its own (such as a password), or it may be useful for launching other, more deadly attacks. If an attack fails, an attacker may use error information provided by the server to launch another more focused attack. For example, an attempt to exploit a path traversal weakness (CWE-22) might yield the full pathname of the installed application. In turn, this could be used to select the proper number of ".." sequences to navigate to the targeted file. An attack using SQL injection (CWE-89) might not initially succeed, but an error message could reveal the malformed query, which would expose query logic and possibly even passwords or other sensitive information used within the query.

**Vulnerable Code:**

    try {
      out = httpResponse.getOutputStream()
    } catch (Exception e) {
      e.printStackTrace(out);
    }

### References
- [CWE-209: Information Exposure Through an Error Message](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-211: Information Exposure Through Externally-Generated Error Message](https://cwe.mitre.org/data/definitions/211.html)

## SMTP Header Injection[<small></small>](#SMTP_HEADER_INJECTION "Permanent link")

_<small>Bug Pattern: <tt>SMTP_HEADER_INJECTION</tt></small>_

Simple Mail Transfer Protocol (SMTP) is a the text based protocol used for email delivery. Like with HTTP, headers are separate by new line separator. If user input is place in a header line, the application should remove or replace new line characters (`CR` / `LF`). You should use a safe wrapper such as [Apache Common Email](https://commons.apache.org/proper/commons-email/userguide.html) and [Simple Java Mail](http://www.simplejavamail.org) which filter special characters that can lead to header injection.

**Vulnerable Code:**

    Message message = new MimeMessage(session);
    message.setFrom(new InternetAddress("noreply@your-organisation.com"));
    message.setRecipients(Message.RecipientType.TO, new InternetAddress[] {new InternetAddress("target@gmail.com")});
    message.setSubject(usernameDisplay + " has sent you notification"); //Injectable API
    message.setText("Visit your ACME Corp profile for more info.");
    Transport.send(message);

**Solution**

Use [Apache Common Email](https://commons.apache.org/proper/commons-email/userguide.html) or [Simple Java Mail](http://www.simplejavamail.org).

### References
- [OWASP SMTP Injection](<https://www.owasp.org/index.php/Testing_for_IMAP/SMTP_Injection_(OTG-INPVAL-011)>)
- [CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)
- [Commons Email: User Guide](https://commons.apache.org/proper/commons-email/userguide.html)
- [Simple Java Mail Website](http://www.simplejavamail.org)
- [StackExchange InfoSec: What threats come from CRLF in email generation?](https://security.stackexchange.com/a/54100/24973)

## Enabling extensions in Apache XML RPC server or client.[<small></small>](#RPC_ENABLED_EXTENSIONS "Permanent link")

_<small>Bug Pattern: <tt>RPC_ENABLED_EXTENSIONS</tt></small>_

Enabling extensions in Apache XML RPC server or client can lead to deserialization vulnerability which would allow an attacker to execute arbitrary code.
It's recommended not to use `setEnabledForExtensions` method of `org.apache.xmlrpc.client.XmlRpcClientConfigImpl` or `org.apache.xmlrpc.XmlRpcConfigImpl`. By default, extensions are disabled both on the client and the server.

### References
- [0ang3el's Blog: Beware of WS-XMLRPC library in your Java App](https://0ang3el.blogspot.com/2016/07/beware-of-ws-xmlrpc-library-in-your.html)
- [CVE-2016-5003 vulnerability reference](https://nvd.nist.gov/vuln/detail/CVE-2016-5003)

## Disabling HTML escaping put the application at risk for XSS[<small></small>](#WICKET_XSS1 "Permanent link")

_<small>Bug Pattern: <tt>WICKET_XSS1</tt></small>_

Disabling HTML escaping put the application at risk for Cross-Site Scripting (XSS).

**Vulnerable Code:**

    add(new Label("someLabel").setEscapeModelStrings(false));

### References
- [Wicket models and forms - Reference Documentation](https://ci.apache.org/projects/wicket/guide/6.x/guide/modelsforms.html)
- [WASC-8: Cross Site Scripting](http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting)
- [OWASP: XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet)
- [OWASP: Top 10 2013-A3: Cross-Site Scripting (XSS)](https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_%28XSS%29)
- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

## Ignoring XML comments in SAML may lead to authentication bypass[<small></small>](#SAML_IGNORE_COMMENTS "Permanent link")

_<small>Bug Pattern: <tt>SAML_IGNORE_COMMENTS</tt></small>_

Security Assertion Markup Language (SAML) is a single sign-on protocol that that used XML. The SAMLResponse message include statements that describe the authenticated user. If a user manage to place XML comments (`<!-- -->`), it may caused issue in the way the parser extract literal value.

For example, let's take the following XML section:

    <saml:Subject><saml:NameID>admin@domain.com<!---->.evil.com</saml:NameID></saml:Subject>

The user identity is `"admin@domain.com<!---->.evil.com"` but it is in fact a text node `"admin@domain.com"`, a comment `""` and a text node `".evil.com"`. When extracting the NameID, the service provider implementation might take first text node or the last one.

**Vulnerable Code:**

    @Bean
    ParserPool parserPool1() {
        BasicParserPool pool = new BasicParserPool();
        pool.setIgnoreComments(false);
        return pool;
    }

**Solution:**

    @Bean
    ParserPool parserPool1() {
        BasicParserPool pool = new BasicParserPool();
        pool.setIgnoreComments(true);
        return pool;
    }

### References
- [Duo Finds SAML Vulnerabilities Affecting Multiple Implementations](https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations)
- [Spring Security SAML and this week's SAML Vulnerability](https://spring.io/blog/2018/03/01/spring-security-saml-and-this-week-s-saml-vulnerability)

## Overly permissive file permission[<small></small>](#OVERLY_PERMISSIVE_FILE_PERMISSION "Permanent link")

_<small>Bug Pattern: <tt>OVERLY_PERMISSIVE_FILE_PERMISSION</tt></small>_

It is generally a bad practices to set overly permissive file permission such as read+write+exec for all users. If the file affected is a configuration, a binary, a script or sensitive data, it can lead to privilege escalation or information leakage.

It is possible that another service, running on the same host as your application, gets compromised. Services typically run under a different user. A compromised service account could be use to read your configuration, add execution instruction to scripts or alter the data file. To limite the damage from other services or local users, you should limited to permission of your application files.

**Vulnerable Code 1 (symbolic notation):**

    Files.setPosixFilePermissions(configPath, PosixFilePermissions.fromString("rw-rw-rw-"));

**Solution 1 (symbolic notation):**

    Files.setPosixFilePermissions(configPath, PosixFilePermissions.fromString("rw-rw----"));

**Vulnerable Code 2 (Object-oriented implementation):**

    Set<PosixFilePermission> perms = new HashSet<>();
    perms.add(PosixFilePermission.OWNER_READ);
    perms.add(PosixFilePermission.OWNER_WRITE);
    perms.add(PosixFilePermission.OWNER_EXECUTE);

    perms.add(PosixFilePermission.GROUP_READ);
    perms.add(PosixFilePermission.GROUP_WRITE);
    perms.add(PosixFilePermission.GROUP_EXECUTE);

    perms.add(PosixFilePermission.OTHERS_READ);
    perms.add(PosixFilePermission.OTHERS_WRITE);
    perms.add(PosixFilePermission.OTHERS_EXECUTE);

**Solution 2 (Object-oriented implementation):**

    Set<PosixFilePermission> perms = new HashSet<>();
    perms.add(PosixFilePermission.OWNER_READ);
    perms.add(PosixFilePermission.OWNER_WRITE);
    perms.add(PosixFilePermission.OWNER_EXECUTE);

    perms.add(PosixFilePermission.GROUP_READ);
    perms.add(PosixFilePermission.GROUP_WRITE);
    perms.add(PosixFilePermission.GROUP_EXECUTE);

### References
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [A guide to Linux Privilege Escalation](https://payatu.com/guide-linux-privilege-escalation/)
- [File system permissions](https://en.wikipedia.org/wiki/File_system_permissions)
