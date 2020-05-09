# Go secure coding

Scan use gosec and staticcheck for analyzing Go projects.

## G102: Bind to all interfaces

Binding to all network interfaces can potentially open up a service to traffic on unintended interfaces, that may not be properly documented or secured. This check test looks for a string pattern “0.0.0.0” that may indicate a hardcoded binding to all network interfaces.

### Incorrect

```go
package main

import (
    "net"
)

func main() {
    net.Listen("tcp", ":8080")
}
```

```go
    l, err := net.Listen("tcp", "0.0.0.0:2000")
```

## G103: Audit the use of unsafe block

Using the unsafe package in Go gives you low-level memory management and many of the strength of the C language but also gives flexibility to the attacker of your application. The pointer arithmetic is one of the examples from the unsafe package which can be used for data leak, memory corruption or even execution of attackers own script.

Also, you should keep in mind that the "unsafe" package is not protected by Go 1 compatibility guidelines.

If you want to ignore this rule you can do it, as usual, using the "exclude" option in the command line interface.

Example code:
```go
package main
import (
    "fmt"
    "unsafe"
)
type Fake struct{}
func (Fake) Good() {}
func main() {
    unsafeM := Fake{}
    unsafeM.Good()
    intArray := [...]int{1, 2}
    fmt.Printf("\nintArray: %v\n", intArray)
    intPtr := &intArray[0]
    fmt.Printf("\nintPtr=%p, *intPtr=%d.\n", intPtr, *intPtr)
    addressHolder := uintptr(unsafe.Pointer(intPtr)) + unsafe.Sizeof(intArray[0])
    intPtr = (*int)(unsafe.Pointer(addressHolder))
    fmt.Printf("\nintPtr=%p, *intPtr=%d.\n\n", intPtr, *intPtr)
}
```

## G104: Audit errors not checked

Really useful feature of Golang is the ability to return a tuple of a result and an error value from a function. There is an unspoken rule in Golang that the result of a function is unsafe until you make check the error value. Many security exploits can be performed when the error value is not checked.

Example code:

```go
package main
import "fmt"
func test() (int,error) {
    return 0, nil
}
func main() {
    v, _ := test()
    fmt.Println(v)
}
```

other example:

```go
package main

import (
    "fmt"
    "io/ioutil"
    "os"
)

func a() error {
    return fmt.Errorf("This is an error")
}

func b() {
    fmt.Println("b")
    ioutil.WriteFile("foo.txt", []byte("bar"), os.ModeExclusive)
}

func c() string {
    return fmt.Sprintf("This isn't anything")
}

func main() {
    _ = a()
    a()
    b()
    c()
}
```

## G106: Audit the use of ssh.InsecureIgnoreHostKey
## G107: Url provided to HTTP request as taint input

Getting an URL from an untrusted source like user input gives the ability of an attacker to redirect your application to bad websites and perform additional attacks. One of the examples is as shown below the http.Get() function issues a GET to the specified URL and if the result is appropriate GET will follow the redirect after calling Client's CheckRedirect function. That means that the attacker can send your application to various places.

This problem can be used to achieve SSRF atttacks via http requests with variable url.

### Incorrect

```go
package main
import (
    "net/http"
    "io/ioutil"
    "fmt"
    "os"
)
func main() {
    url := os.Getenv("tainted_url")
    resp, err := http.Get(url)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
            panic(err)
    }
    fmt.Printf("%s", body)
}
```

```go
package main

import (
    "fmt"
    "io/ioutil"
    "net/http"
)

var url string = "https://www.slscan.io"

func main() {

    resp, err := http.Get(url)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        panic(err)
    }
    fmt.Printf("%s", body)
}
```

## G108: Profiling endpoint automatically exposed on /debug/pprof
## G109: Potential Integer overflow made by strconv.Atoi result conversion to int16/32
## G110: Potential DoS vulnerability via decompression bomb
## G201: SQL query construction using format string

SQL injection is one of the top security issues developers make and the consequences of this can be severe. Using the format string function in the fmt Golang package to dynamically create an SQL query can easily create a possibility for SQL injection. The reason is that the format string function doesn't escape special characters like ' and it's easy to add second SQL command in the format string.

Examples of problematic code:

```go
package main
import (
    "database/sql"
    "fmt"
    "os"
)
func main(){
    db, err := sql.Open("sqlite3", ":memory:")
    if err != nil {
        panic(err)
    }
    q := fmt.Sprintf("SELECT * FROM foo where name = '%s'", os.Args[1])
    rows, err := db.Query(q)
    if err != nil {
        panic(err)
    }
    defer rows.Close()
}
```

## G202: SQL query construction using string concatenation

### Incorrect

```go

import (
    "database/sql"
)

var staticQuery = "SELECT * FROM foo WHERE age < "

func main() {
    db, err := sql.Open("sqlite3", ":memory:")
    if err != nil {
        panic(err)
    }
    var gender string = "M"
    rows, err := db.Query("SELECT * FROM foo WHERE gender = " + gender)
    if err != nil {
        panic(err)
    }
    defer rows.Close()
}
```

### Correct

Two of the ways to escape SQL injection when using Golang are:

- use static queries

```go
package main
import (
        "database/sql"
)
const staticQuery = "SELECT * FROM foo WHERE age < 32"
func main(){
        db, err := sql.Open("sqlite3", ":memory:")
        if err != nil {
            panic(err)
        }
        rows, err := db.Query(staticQuery)
        if err != nil {
            panic(err)
        }
        defer rows.Close()
}
```

- Use the database/sql By using the database/sql package along with argument placeholders you are able to construct SQL statements that are automatically escaped properly. The key distinction here is that you aren’t trying to construct the SQL statement yourself, but instead you are providing arguments that can be easily escaped. The underlying driver for database/sql will ultimately be aware of what special characters it needs to handle and will escape them for you, preventing any nefarious SQL from running.

```go
package main
import (
        "database/sql"
        "bufio"

)
func main(){
        db, err := sql.Open("sqlite3", ":memory:")
        if err != nil {
            panic(err)
        }
        in := bufio.NewReader(os.Stdin)
        name, err := in.ReadString('\n')
        if err != nil {
            panic(err)
        }
        rows, err := db.Query("SELECT * FROM foo WHERE name = ?", name)
        if err != nil {
            panic(err)
        }
        defer rows.Close()
}
```

It is highly recommended to use the database/sql package in Golang instead of fmt package for SQL queries.

## G203: Use of unescaped data in HTML templates
## G204: Audit use of command execution
## G301: Poor file permissions used when creating a directory
## G302: Poor file permissions used with chmod
## G303: Creating tempfile using a predictable path
## G304: File path provided as taint input

Trying to open a file provided as an input in a variable. The content of this variable might be controlled by an attacker who could change it to hold unauthorised file paths form the system. In this way, it is possible to exfiltrate confidential information or such.

### Incorrect

```go
package main

import (
    "fmt"
    "io/ioutil"
    "strings"
)

func main() {
    repoFile := "path_of_file"
    byContext, err := ioutil.ReadFile(repoFile)
    if err != nil {
        panic(err)
    }
    fmt.Printf("%s", string(byContext))
}
```

### Correct

```go
package main

import (
    "fmt"
    "io/ioutil"
    "path/filepath"
    "strings"
)

func main() {
    repoFile := "path_of_file"
    byContext, err := ioutil.ReadFile(filepath.Clean(repoFile))
    if err != nil {
        panic(err)
    }
    fmt.Printf("%s", string(byContext))
}
```

## G305: File traversal when extracting zip archive
## G306: Poor file permissions used when writing to a new file
## G307: Deferring a method which returns an error
## G401: Detect the usage of DES, RC4, MD5 or SHA1
## G402: Look for bad TLS connection settings
## G403: Ensure minimum RSA key length of 2048 bits
## G404: Insecure random number source (rand)
## G501: Import blacklist: crypto/md5
## G502: Import blacklist: crypto/des
## G503: Import blacklist: crypto/rc4
## G504: Import blacklist: net/http/cgi
## G505: Import blacklist: crypto/sha1
## G601: Implicit memory aliasing of items from a range statement

The rules used by staticcheck can be found [here](https://staticcheck.io/docs/checks)
