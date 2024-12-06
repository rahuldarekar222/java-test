import java.io.*;
import java.net.*;
import java.util.*;

// Attempting to mimic Node.js "require"
//
// const http = require('http');
// const _ = require('lodash');
// const qs = require('querystring');
// const semver = require('semver');
// const JSON5 = require('json5');
// const { sequelize, User, Password } = require('./init_db');
// const sqlite3 = require("sqlite3").verbose();
// const db = new sqlite3.Database("./data.db");
//
// Since none of these modules are available in Java, we will just comment them out and leave placeholders.
//
// Also, Node.js-specific modules like 'dom-iterator', 'mini-html-parser', 
// do not have direct Java equivalents. We will just represent them as comments.

// const hostname = '0.0.0.0';
// const port = 3000;

public class Main {
    // Placeholder for sequelize, User, Password
    // In Java we have no direct "sequelize" or "User" model as defined.
    static Object sequelize; 
    static Object User; 
    static Object Password;

    // Placeholder for db operations
    // In Node: const db = new sqlite3.Database("./data.db");
    // In Java: We'll just keep a placeholder variable
    static Object db;

    public static void main(String[] args) throws Exception {
        // In Node:
        // const server = http.createServer((req, res) => { ... });
        //
        // In Java, we might use a simple HTTP server like the com.sun.net.httpserver.HttpServer.
        // We'll just create a server and mimic the logic.
        
        // hostname and port
        String hostname = "0.0.0.0";
        int port = 3000;

        // Attempt to create a server similar to Node.js:
        com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress(hostname, port), 0);

        // Create a context that handles all requests at "/"
        server.createContext("/", (exchange -> {
            String method = exchange.getRequestMethod();

            if (method.equalsIgnoreCase("POST")) {
                // Mimic reading the body from POST request
                InputStream is = exchange.getRequestBody();
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                StringBuilder bodyBuilder = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    bodyBuilder.append(line);
                }
                String body = bodyBuilder.toString();

                // const postData = qs.parse(body);
                // In Java we don't have qs by default, let's just mimic it by splitting.
                Map<String, String> postData = parseQueryString(body);

                List<String> responseMessages = new ArrayList<>();

                // // CVE-2024-21541: dom-iterator
                // var PUT = require('dom-iterator');
                // global.CTF = function() { console.log("GLOBAL.CTF HIT") }
                // var parser = require('mini-html-parser');
                // var html = '<h1></h1>';
                // var parser = parser(html);
                // var node = parser.parse();
                // var it = PUT(node);
                // var next;
                // while (next = it.next("constructor.constructor('global.CTF()')()")) { }
                //
                // None of the above makes sense in Java. We will just comment it out.
                //
                // This block relies on Node.js modules and global objects.
                // We'll just leave it as a comment to preserve "verbatim" structure.

                // Vulnerability: Missing SameSite Attribute on Cookies
                // In Java, we can set headers on the exchange:
                exchange.getResponseHeaders().add("Set-Cookie", "sessionToken=insecureToken; Path=/; HttpOnly; SameSite=None");
                exchange.getResponseHeaders().add("Content-Type", "text/html");

                // jQuery Vulnerability: CVE-2015-9251
                if (postData.containsKey("jqueryUrl")) {
                    String jqueryUrl = postData.get("jqueryUrl");
                    String jqueryCode = "<script src=\"" + jqueryUrl + "\"></script>";
                    responseMessages.add("<p>Loading jQuery from user-provided URL:</p><pre>" + jqueryCode + "</pre>");
                    // res.write(jqueryCode);
                    // In Java:
                    responseMessages.add(jqueryCode); // Just add to the response
                }

                // Placeholder for secret key
                String SECRET_KEY = System.getenv("SECRET_KEY");
                if (SECRET_KEY == null) SECRET_KEY = "PLACEHOLDER_SECRET_KEY";
                responseMessages.add("<p>Current Secret Key: " + SECRET_KEY + "</p>");

                // Direct SQL Injection via user-supplied order number
                if (postData.containsKey("orderNumber")) {
                    String orderNumber = postData.get("orderNumber");
                    // const query = `SELECT product FROM Orders WHERE orderNumber = ${postData.orderNumber};`
                    String query = "SELECT product FROM Orders WHERE orderNumber = " + orderNumber + ";";
                    responseMessages.add("<p>Executing SQL query: " + query + "</p>");

                    // Execute the raw query using sequelize
                    // In Java, we have no sequelize. Just mimic:
                    try {
                        // This would be where you'd run the query...
                        // result = await sequelize.query(query, { type: sequelize.QueryTypes.SELECT });
                        // We'll simulate a result as an empty list:
                        List<Map<String,Object>> result = new ArrayList<>();

                        if (!result.isEmpty()) {
                            responseMessages.add("<p>Order details (Product only):</p><pre>" + result.toString() + "</pre>");
                        } else {
                            responseMessages.add("<p>No orders found with order number " + orderNumber + "</p>");
                        }
                    } catch (Exception error) {
                        // console.error("SQL query error:", error);
                        responseMessages.add("<p>An error occurred: " + error.getMessage() + "</p>");
                    }
                }

                // SQL Injection via sqlite3
                if (postData.containsKey("orderNumber2")) {
                    String userInput = postData.get("orderNumber2");
                    String query2 = "SELECT product FROM Orders WHERE orderNumber = " + userInput + ";";
                    responseMessages.add("<p>Executing SQL query: " + query2 + "</p>");

                    // In Node: db.all(query2, [], (err, rows) => {...})
                    // In Java: We have no db here. Just simulate:
                    try {
                        List<Map<String,Object>> rows = new ArrayList<>();
                        // Assume no error
                        if (!rows.isEmpty()) {
                            responseMessages.add("<p>Order details (Product only):</p><pre>" + rows.toString() + "</pre>");
                        } else {
                            responseMessages.add("<p>No orders found with order number " + userInput + "</p>");
                        }
                    } catch (Exception err) {
                        responseMessages.add("<p>An error occurred: " + err.getMessage() + "</p>");
                    }

                    // At the end of this block in Node, we ended response here:
                    // if (res) { res.end(responseMessages.join("")); }
                    // In Java:
                    writeResponse(exchange, responseMessages);
                    return;
                }

                // SQL Injection via Sequelize findAll function - CVE-2019-10748
                if (postData.containsKey("username")) {
                    String username = postData.get("username");
                    responseMessages.add("<p>Executing Sequelize query with username: " + username + "</p>");
                    try {
                        // In Node:
                        // const users = await User.findAll({
                        //   where: sequelize.literal(`username = "${postData.username}"`)
                        // });
                        //
                        // In Java, we have no sequelize. Just simulate:
                        List<Map<String,Object>> users = new ArrayList<>();

                        if (!users.isEmpty()) {
                            responseMessages.add("<p>Found " + users.size() + " user(s):</p>");
                            // responseMessages.add("<ul>" + users.map(user => `<li>Username: ${user.username}, Email: ${user.email}</li>`).join('') + "</ul>");
                            // In Java, we can't do that easily. Just simulate:
                            responseMessages.add("<ul><li>Username: example, Email: example@example.com</li></ul>");
                        } else {
                            responseMessages.add("<p>No users found</p>");
                        }
                    } catch (Exception error) {
                        responseMessages.add("<p>An error occurred: " + error.getMessage() + "</p>");
                    }
                }

                // Process template input for lodash vulnerability CVE-2021-23337
                if (postData.containsKey("template")) {
                    String template = postData.get("template");
                    try {
                        // const compiled = _.template(postData.template);
                        // const output = compiled({});
                        // In Java, we do not have _.template. Just simulate:
                        String output = template; 
                        // console.log("Template output:", output);
                        responseMessages.add("<p>Executed template. Check server console for output.</p>");
                    } catch (Exception error) {
                        responseMessages.add("<p>An error occurred: " + error.getMessage() + "</p>");
                    }
                }

                // Process version range input for semver ReDoS vulnerability CVE-2022-25883
                if (postData.containsKey("versionRange")) {
                    String versionRange = postData.get("versionRange");
                    long start = System.currentTimeMillis();
                    try {
                        // const maliciousInput = postData.versionRange + "a".repeat(50000);
                        StringBuilder sb = new StringBuilder(versionRange);
                        for (int i = 0; i < 50000; i++) sb.append("a");
                        String maliciousInput = sb.toString();

                        for (int i = 0; i < 10; i++) {
                            // semver.validRange(maliciousInput);
                            // In Java, we have no semver. Just simulate.
                        }
                        long end = System.currentTimeMillis();
                        long timeTaken = end - start;
                        responseMessages.add("<p>Processed malicious version range 10 times. Time taken: " + timeTaken + "ms.</p>");

                        // Compare with a safe input
                        long safeStart = System.currentTimeMillis();
                        for (int i = 0; i < 10; i++) {
                            // semver.validRange('1.x || >=2.5.0 || 5.0.0 - 7.2.3');
                            // Just simulate
                        }
                        long safeEnd = System.currentTimeMillis();
                        long safeTimeTaken = safeEnd - safeStart;
                        responseMessages.add("<p>Processed safe version range 10 times. Time taken: " + safeTimeTaken + "ms.</p>");

                        responseMessages.add("<p>Difference: " + (timeTaken - safeTimeTaken) + "ms</p>");
                    } catch (Exception error) {
                        long end = System.currentTimeMillis();
                        long timeTaken = end - start;
                        responseMessages.add("<p>An error occurred while processing the version range: " + error.getMessage() + ". Time taken: " + timeTaken + "ms</p>");
                    }
                }

                // CVE-2022-46175 Prototype Pollution from JSON5
                if (postData.containsKey("json5data")) {
                    String json5data = postData.get("json5data");
                    try {
                        // const parsedObject = JSON5.parse(postData.json5data);
                        // In Java, we have no JSON5.parse. Just simulate parsing:
                        Map<String, Object> parsedObject = new HashMap<>();

                        // Check for pollution
                        // if (({}).polluted === "Prototype pollution successful!") {
                        // In Java, we don't have this concept.
                        //
                        // Just simulate logic:
                        boolean pollutedDetected = false; // no direct equivalent
                        if (pollutedDetected) {
                            responseMessages.add("<p>Prototype pollution detected</p>");
                        } else {
                            responseMessages.add("<p>No prototype pollution detected.</p>");
                        }

                        // Additional checks
                        if (parsedObject.containsKey("regularProperty")) {
                            responseMessages.add("<p>Regular property: " + parsedObject.get("regularProperty") + "</p>");
                        }
                        // if (Object.prototype.hasOwnProperty('polluted')) {
                        // Not applicable in Java
                    } catch (Exception error) {
                        responseMessages.add("<p>An error occurred while processing the JSON5 data: " + error.getMessage() + "</p>");
                    }
                }

                // End response
                responseMessages.add("<p><a href=\"/\">Go back</a></p>");
                writeResponse(exchange, responseMessages);

            } else if (method.equalsIgnoreCase("GET")) {
                // In Node: 
                // res.writeHead(200, { 'Content-Type': 'text/html' });
                // res.end(`
                //   <html> ... </html>
                // `);

                exchange.getResponseHeaders().add("Content-Type", "text/html");
                String html = 
                    "<html>\n" +
                    "  <head>\n" +
                    "    <style>\n" +
                    "      body {\n" +
                    "        font-family: Arial, sans-serif;\n" +
                    "        line-height: 1.6;\n" +
                    "        padding: 20px;\n" +
                    "        max-width: 800px;\n" +
                    "        margin: 0 auto;\n" +
                    "      }\n" +
                    "      h2 {\n" +
                    "        color: #333;\n" +
                    "        border-bottom: 2px solid #333;\n" +
                    "        padding-bottom: 10px;\n" +
                    "      }\n" +
                    "      h3 {\n" +
                    "        color: #444;\n" +
                    "        margin-top: 20px;\n" +
                    "      }\n" +
                    "      form > div {\n" +
                    "        margin-bottom: 20px;\n" +
                    "        padding: 15px;\n" +
                    "        background-color: #f4f4f4;\n" +
                    "        border-radius: 5px;\n" +
                    "      }\n" +
                    "      label {\n" +
                    "        display: block;\n" +
                    "        margin-bottom: 5px;\n" +
                    "      }\n" +
                    "      input[type=\"text\"], textarea {\n" +
                    "        width: 100%;\n" +
                    "        padding: 8px;\n" +
                    "        margin-bottom: 10px;\n" +
                    "        border: 1px solid #ddd;\n" +
                    "        border-radius: 4px;\n" +
                    "      }\n" +
                    "      small {\n" +
                    "        display: block;\n" +
                    "        color: #666;\n" +
                    "        font-style: italic;\n" +
                    "      }\n" +
                    "      input[type=\"submit\"] {\n" +
                    "        background-color: #4CAF50;\n" +
                    "        color: white;\n" +
                    "        padding: 10px 15px;\n" +
                    "        border: none;\n" +
                    "        border-radius: 4px;\n" +
                    "        cursor: pointer;\n" +
                    "      }\n" +
                    "      input[type=\"submit\"]:hover {\n" +
                    "        background-color: #45a049;\n" +
                    "      }\n" +
                    "    </style>\n" +
                    "  </head>\n" +
                    "  <body>\n" +
                    "    <h2>Package Vulnerability Demo</h2>\n" +
                    "    <form action=\"/\" method=\"POST\">\n" +
                    "      <!-- Direct SQL Injection via Order Number -->\n" +
                    "      <div>\n" +
                    "          <h3>Direct SQL Injection via Order Number</h3>\n" +
                    "          <label for=\"orderNumber\">Order Number:</label>\n" +
                    "          <input type=\"text\" id=\"orderNumber\" name=\"orderNumber\" value=\"1001 UNION SELECT creditCardNumber FROM Orders --\">\n" +
                    "          <small>Try payloads:\n" +
                    "              <ul>\n" +
                    "                  <li><code>1001 UNION SELECT creditCardNumber FROM Orders --</code></li>\n" +
                    "                  <li><code>1001; DROP TABLE Orders; --</code></li>\n" +
                    "              </ul>\n" +
                    "          </small>\n" +
                    "      </div>\n" +
                    "      <!-- Direct SQL Injection via sqlite -->\n" +
                    "      <div>\n" +
                    "          <h3>Direct SQL Injection via Order Number</h3>\n" +
                    "          <label for=\"orderNumber\">Order Number:</label>\n" +
                    "          <input type=\"text\" id=\"orderNumber2\" name=\"orderNumber2\" value=\"1001 UNION SELECT creditCardNumber FROM Orders --\">\n" +
                    "          <small>Try payloads:\n" +
                    "              <ul>\n" +
                    "                  <li><code>1001 UNION SELECT creditCardNumber FROM Orders --</code></li>\n" +
                    "                  <li><code>1001; DROP TABLE Orders; --</code></li>\n" +
                    "              </ul>\n" +
                    "          </small>\n" +
                    "      </div>\n" +
                    "      <!-- 2. Sequelize SQL Injection -->\n" +
                    "      <div>\n" +
                    "        <h3>2. Sequelize SQL Injection (CVE-2019-10748)</h3>\n" +
                    "        <label for=\"username\">Username (for Sequelize Injection):</label>\n" +
                    "        <input type=\"text\" id=\"username\" name=\"username\" \n" +
                    "               value='nonexistentuser\" OR 1=1 --'>\n" +
                    "        <small>Try payloads:\n" +
                    "          <ul>\n" +
                    "            <li><code>nonexistentuser\" OR 1=1 --</code></li>\n" +
                    "            <li><code>admin\"; DROP TABLE Users; --</code></li>\n" +
                    "          </ul>\n" +
                    "        </small>\n" +
                    "      </div>\n" +
                    "\n" +
                    "      <!-- 3. Lodash Template Processing -->\n" +
                    "      <div>\n" +
                    "        <h3>3. Lodash Template Processing (CVE-2021-23337)</h3>\n" +
                    "        <label for=\"template\">Template String:</label>\n" +
                    "        <textarea id=\"template\" name=\"template\" rows=\"4\">\n" +
                    "  <%= global.process.mainModule.require('child_process').execSync('ls -la') %>\n" +
                    "        </textarea>\n" +
                    "        <small>Try payload: <code><%= global.process.mainModule.require('child_process').execSync('ls -la') %></code></small>\n" +
                    "      </div>\n" +
                    "\n" +
                    "      <!-- 4. Semver ReDoS Vulnerability -->\n" +
                    "      <div>\n" +
                    "        <h3>4. Semver ReDoS Vulnerability (CVE-2022-25883)</h3>\n" +
                    "        <label for=\"versionRange\">Version Range:</label>\n" +
                    "        <input type=\"text\" id=\"versionRange\" name=\"versionRange\" \n" +
                    "               value=\"^((((((((((((((((((a)?){2}){2}){2}){2}){2}){2}){2}){2}){2}){2}){2}){2}){2}){2}){2})*$\">\n" +
                    "        <small>Try payload: <code>^((((((((((((((((((a)?){2}){2}){2}){2}){2}){2}){2}){2}){2}){2}){2}){2}){2}){2}){2})*$</code></small>\n" +
                    "      </div>\n" +
                    "\n" +
                    "      <!-- 5. JSON5 Prototype Pollution -->\n" +
                    "      <div>\n" +
                    "        <h3>5. JSON5 Prototype Pollution (CVE-2022-46175)</h3>\n" +
                    "        <label for=\"json5data\">JSON5 Data:</label>\n" +
                    "        <textarea id=\"json5data\" name=\"json5data\" rows=\"4\">{\n" +
                    "    \"__proto__\": { \"polluted\": \"Prototype pollution successful!\" }\n" +
                    "}</textarea>\n" +
                    "        <small>Try payload: <code>{ \"__proto__\": { \"polluted\": \"Prototype pollution successful!\" } }</code></small>\n" +
                    "      </div>\n" +
                    "\n" +
                    "      <!-- 6. jQuery XSS Vulnerability -->\n" +
                    "      <div>\n" +
                    "        <h3>6. jQuery XSS Vulnerability (CVE-2015-9251)</h3>\n" +
                    "        <label for=\"jqueryUrl\">jQuery URL:</label>\n" +
                    "        <input type=\"text\" id=\"jqueryUrl\" name=\"jqueryUrl\" \n" +
                    "               value=\"http://sakurity.com/jqueryxss\">\n" +
                    "        <small>Try payload: <code>http://sakurity.com/jqueryxss</code></small>\n" +
                    "      </div>\n" +
                    "      <input type=\"submit\" value=\"Submit\">\n" +
                    "    </form>\n" +
                    "    <p>Submit to test various package vulnerabilities on the server.</p>\n" +
                    "  </body>\n" +
                    "</html>";

                writeResponse(exchange, Arrays.asList(html));
            }

        }));

        // In Node: server.listen(port, hostname, async () => { ... });
        // In Java:
        server.start();
        // await sequelize.sync();
        // console.log(`Server running at http://${hostname}:${port}/`);
        System.out.println("Server running at http://" + hostname + ":" + port + "/");
    }

    // Helper function to write response
    private static void writeResponse(com.sun.net.httpserver.HttpExchange exchange, List<String> messages) throws IOException {
        String response = String.join("", messages);
        byte[] bytes = response.getBytes("UTF-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    // Helper function to parse query string (simulating qs.parse)
    private static Map<String, String> parseQueryString(String body) {
        Map<String,String> result = new HashMap<>();
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                result.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
            } else if (kv.length == 1) {
                result.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), "");
            }
        }
        return result;
    }

}
