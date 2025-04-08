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

## Basic Obfuscation
### Minifying JavaScript code
A common way of reducing the readability of a snippet of JavaScript code while keeping it fully functional is JavaScript minification. Code minification means having the entire code in a single (often very long) line. Many tools can help us minify JavaScript code, like javascript-minifier. Usually, minified JavaScript code is saved with the extension .min.js.

### Packing JavaScript code

BeautifyTools is a common tool to obfuscate code. 
![image](https://github.com/user-attachments/assets/80966b14-f007-46dc-b4a9-31c18a62d724)
A packer obfuscation tool usually attempts to convert all words and symbols of the code into a list or a dictionary and then refer to them using the (p,a,c,k,e,d) function to re-build the original code during execution. The (p,a,c,k,e,d) can be different from one packer to another. 

## Advanced Obfuscation
https://obfuscator.io is an advanced obfuscation tool making code unreadable for humans.
![image](https://github.com/user-attachments/assets/8cf559af-fa50-4159-abb9-f331b9b0287a)
There are many other JavaScript obfuscators, like JSF,JJ Encode, or AA Encode. However, such obfuscators usually make code execution/compilation very slow, so it is not recommended to be used unless for an obvious reason, like bypassing web filters or restrictions.

## Deobfuscation

#### Beautify
We see that the current code we have is all written in a single line. This is known as Minified JavaScript code. In order to properly format the code, we need to Beautify our code. The most basic method for doing so is through our Browser Dev Tools.

For example, if we were using Firefox, we can open the browser debugger with [ CTRL+SHIFT+Z ], and then click on our script secret.js. This will show the script in its original formatting, but we can click on the '{ }' button at the bottom, which will Pretty Print the script into its proper JavaScript formatting.
![image](https://github.com/user-attachments/assets/21632db3-497e-43e7-9f8e-4fdc0e18b8b5)


#### Deobfuscate

One good online tool is UnPacker.


![image](https://github.com/user-attachments/assets/81b1bb7b-32a4-4da4-aef3-b72fb748884f)


Many techniques can further obfuscate the code and make it less readable by humans and less detectable by systems. For that reason, you will very often find obfuscated code containing encoded text blocks that get decoded upon execution. We will cover 3 of the most commonly used text encoding methods:

- base64 - base64 encoding is usually used to reduce the use of special characters. The length of base64 encoded strings has to be in a multiple of 4. If the resulting output is only 3 characters long, for example, an extra = is added as padding.

If we want to decode any base64 encoded string, we can use base64 -d in a pipe |

- hex - Any string encoded in hex would be comprised of hex characters only, which are 16 characters only: 0-9 and a-f.

To decode a hex encoded string, we can pipe the encoded string to xxd -p -r

- Caesar/Rot13 - Another common -and very old- encoding technique is a Caesar cipher, which shifts each letter by a fixed number. 

There isn't a specific command in Linux to do rot13 encoding. However, it is fairly easy to create our own command to do the character shifting:

```
thossa00@htb[/htb]$ echo https://www.hackthebox.eu/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'

uggcf://jjj.unpxgurobk.rh/
```

We can use the same previous command to decode rot13 as well:

```
thossa00@htb[/htb]$ echo uggcf://jjj.unpxgurobk.rh/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'

https://www.hackthebox.eu/
```

Another option to encode/decode rot13 would be using an online tool, like rot13. Some tools can help us automatically determine the type of encoding, like Cipher Identifier. ccd

Decoded strings can you used in HTB for HTTP Requests to grab more information ie. 
```
curl -s http://94.237.58.55:34463/keys.php/ -X POST -d "key=sample"
echo 4150495f70336e5f37333537316e365f31355f66756e | xxd -p -r
curl -s http://94.237.58.55:34463/keys.php/ -X POST -d "key=API_p3n_73571n6_15_fun"
```

The following is a summary of what we learned:

First, we uncovered the HTML source code of the webpage and located the JavaScript code.
Then, we learned about various ways to obfuscate JavaScript code.
After that, we learned how to beautify and deobfuscate minified and obfuscated JavaScript code.
Next, we went through the deobfuscated code and analyzed its main function
We then learned about HTTP requests and were able to replicate the main function of the obfuscated JavaScript code.
Finally, we learned about various methods to encode and decode strings.
