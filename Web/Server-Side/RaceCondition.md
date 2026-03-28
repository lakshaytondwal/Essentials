# Race Conditions

## Exploitation

In this scenario

These are the credentials for two users:

* User1: `07799991337`
* Password: `pass1234`

And

* User2: `07113371111`
* Password: `pass1234`

This web application belongs to a mobile operator and allows phone credit transfer. In this demo, we will check if the system is susceptible to a race condition vulnerability and try to exploit it by transferring more credit than we have in our account.

First, we need to explore and study how the target web application receives HTTP requests and how it responds to them. Using Burp Suite Proxy, Using the bundled browser, we can browse the target site and study how it processes our HTTP requests.

Log in to either of the accounts and click the Pay & Recharge button. Let’s make a credit transfer: click the Transfer button and enter the mobile number of the other account along with the amount you want to transfer. You can try to transfer an amount that exceeds your current balance and a small amount, such as $1, to see how the system responds in each case.

### Burp Suite: Repeater

In the image below, we can see:

1. A `POST` request
2. The details show the target phone number and a transfer amount of $1.5
3. In the response, we can infer that the transaction is successful

![img](/img/RaceCondition/1.png)

Now that we have seen how the system reacts to valid and invalid requests, let’s see if we can exploit a race condition. Right-click on the `POST` request you want to duplicate and choose **Send to Repeater**.

![img](/img/RaceCondition/2.png)

In the Repeater tab, as shown in the numbered screenshots below:

1. Click on the `+` icon next to the received request tab and select **Create tab group**
2. Assign a group name, and include the tab of the request you just sent to the importer before clicking **Create**
3. Right-click on the request tab and choose **Duplicate tab** (you can also press **CTRL+R** multiple times)
4. As a starting point, we will duplicate it 20 times
5. Next to the Send button, the arrow pointed downwards will bring a menu to decide how you want to send the duplicated requests

![img](/img/RaceCondition/3.png)

![img](/img/RaceCondition/4.png)

Next, we will exploit the target application by sending the duplicated request. Using the built-in options in Burp Suite Repeater, the drop-down arrow offers the following choices:

* Send group in sequence (single connection)
* Send group in sequence (separate connections)
* Send group in parallel

**Send Group in Sequence over a Single Connection:**

This option establishes a single connection to the server and sends all the requests in the group’s tabs before closing the connection. This can be useful for testing for potential client-side desync vulnerabilities.

**Send Group in Sequence over Separate Connections:**

As the name suggests, this option establishes a TCP connection, sends a request from the group, and closes the TCP connection before repeating the process for the subsequent request.

We tested this option to attack the web application. The screenshot below shows 21 TCP connections for the different POST requests in the group we sent.

* The first group (labelled 1) comprises five successful requests. We could confirm that they were successful by checking the respective responses. Furthermore, we noticed that each took around 3 seconds, as indicated by the duration (labelled 3).
* The second group (labelled 2) shows sixteen denied requests. The duration was around four milliseconds. It is interesting to check the Relative Start time as well.

![img](/img/RaceCondition/5.png)

The screenshot below shows the whole TCP connection for a request. We can confirm that the `POST` request was sent in a single packet.

![img](/img/RaceCondition/6.png)

**Send Request Group in Parallel:**

Choosing to send the group’s requests in parallel would trigger the Repeater to send all the requests in the group at once. In this case, we notice the following, as shown in the screenshot below:

* In the Relative Start column, we notice that all 21 packets were sent within a window of 0.5 milliseconds (labelled 1).
* All 21 requests were successful; they resulted in a successful credit transfer. Each request took around 3.2 seconds to complete (labelled 2).

![img](/img/RaceCondition/7.png)

By paying close attention to the screenshot above, we notice that each request led to 12 packets; however, in the previous attempt (send in sequence), we see that each request required only 10 packets. Why did this happen?

According to [Sending Grouped HTTP Requests](https://portswigger.net/burp/documentation/desktop/tools/repeater/send-group) documentation, when sending in parallel, Repeater implements different techniques to synchronize the requests’ arrival at the target, i.e., they arrive within a short time frame. The synchronization technique depends on the HTTP protocol being used:

* In the case of `HTTP/2+`, the Repeater tries to send the whole group in a single packet. In other words, a single TCP packet would carry multiple requests.
* In the case of `HTTP/1`, the Repeater resorts to last-byte synchronization. This trick is achieved by withholding the last byte from each request. Only once all packets are sent without the last-byte are the last-byte of all the requests sent. The screenshot below shows our `POST` request sent over two packets.

![img](/img/RaceCondition/8.png)

---

## Detection & Mitigation

### Detection

Detecting race conditions from the business owner’s perspective can be challenging. If a few users redeemed the same gift card multiple times, it would most likely go unnoticed unless the logs are actively checked for certain behaviours. Considering that race conditions can be used to exploit even more subtle vulnerabilities, it is clear that we need the help of penetration testers and bug bounty hunters to try to discover such vulnerabilities and report their findings.

Penetration testers must understand how the system behaves under normal conditions when enforced controls are enforced. The controls can be: use once, vote once, rate once, limit to balance, and limit to one every 5 minutes, among others. The next step would be to try to circumvent this limit by exploiting race conditions. Figuring out the different system’s states can help us make educated guesses about time windows where a race condition can be exploited. Tools such as Burp Suite Repeater can be a great starting point.

### Mitigation

* **Synchronization Mechanisms:** Modern programming languages provide synchronization mechanisms like locks. Only one thread can acquire the lock at a time, preventing others from accessing the shared resource until it’s released.
* **Atomic Operations:** Atomic operations refer to indivisible execution units, a set of instructions grouped together and executed without interruption. This approach guarantees that an operation can finish without being interrupted by another thread.
* **Database Transactions:** Transactions group multiple database operations into one unit. Consequently, all operations within the transaction either succeed as a group or fail as a group. This approach ensures data consistency and prevents race conditions from multiple processes modifying the database concurrently.
