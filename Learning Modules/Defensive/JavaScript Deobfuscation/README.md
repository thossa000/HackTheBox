# JavaScript Deobfuscation
Notes for the HackTheBox learning module, JavaScript Deobfuscation

### JavaScript
Javascript can be internally written between <script> elements or written into a separate .js file and referenced within the HTML code.

We can see this by reading the HTML code using the CTRL+U command to view.
```
<script src="secret.js"></script>
```

We can read the script by clicking on secret.js, which should take us directly into the script.

## What is Obfuscation
Obfuscation is a technique used to make a script more difficult to read by humans but allows it to function the same from a technical point of view, though performance may be slower. This is usually achieved automatically by using an obfuscation tool, which takes code as an input, and attempts to re-write the code in a way that is much more difficult to read, depending on its design.

The following is an example of a simple JavaScript code being obfuscated:
![image](https://github.com/user-attachments/assets/53a68b19-89b4-409c-990a-d3df223f4c4c)

JavaScript is usually used within browsers at the client-side, and the code is sent to the user and executed in cleartext. This is why obfuscation is very often used with JavaScript.

The most common usage of obfuscation is for malicious actions. It is common for attackers and malicious actors to obfuscate their malicious scripts to prevent Intrusion Detection and Prevention systems from detecting their scripts
