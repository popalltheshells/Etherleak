# Etherleak
During a pentest, I found Etherleak-vulnerable NIC - tried to understand it a bit more since this is the first time I see it in person. Decided to whip out Python script to help capture, split, and validate the response packets to see if a leak happens. Of course, for an actual sensitive info leak, you have to capture hundreds of thousands of packets, and decipher it in hope that there is something sensitive info in the leaked memory. This is just a PoC to validate the Nessus result.

![image](https://github.com/user-attachments/assets/401d5dc0-b996-42e5-906b-5bbf8951f8e9)
