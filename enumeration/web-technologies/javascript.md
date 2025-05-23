# Javascript

## Dissasembly .class files with javap

```bash
javap -c $FILE
```

## Variables

There are 3 types of variables in JavaScript: **var**, **let**, and **const**.

Quick Overview:

* let: If a variable is going to be reassigned later within the application, this is the ideal variable type to use.
* var: It's better to use either let or const for variables, but this variable type will still work and is still used in applications to this day. This variable can be updated and re-declared.
* const: If the variable will never change or won't be reassigned anywhere else in the application, this keyword is the best option.

Good things to remember:

* The **var** variable is globally scoped and can be updated and re-declared.
* The **let** variable is block-scoped and can be updated but not re-declared.
* The **const** variable is block-scoped and cannot be updated or re-declared.

**Global Scope:** A variable declared outside a function. This means all scripts and functions on a web application or webpage can access this variable.

**Block Scope:** A variable declared inside a block. This means we can use these variables inside of loops, if statements, or other declarations within curly brackets and have them be only used for that declaration instead of the entire application having access to it.

## Functions

Functions are one of the most vital parts of programming. Due to how important functions are, there will be a lot of things we don't cover, but remember that functions are going to be vital to any applications you write.

\*ECMAScript 6 is the most popular version of JavaScript. There are a lot of important differences between ES5 and ES6, we focus mainly on ES6 in this room, but knowing past versions can help improve your knowledge of the language and logic of JavaScript.

This is a function in **ES6** (ECMAScript 6):

```java
const func = (a, b) => {
    let nums = a * b;
    console.log(nums); // Outputs 250
}
func(25, 10);
```

**ES5**:

```java
function func(a, b) // Everything inside of the parenthesis defines our parameter(s)
{
    let nums = a * b;
    console.log(nums); // Outputs 250
}
func(25, 10);
```

### eval()

[https://medium.com/@sebnemK/node-js-rce-and-a-simple-reverse-shell-ctf-1b2de51c1a44](https://medium.com/@sebnemK/node-js-rce-and-a-simple-reverse-shell-ctf-1b2de51c1a44)

## Deobfuscation

[http://www.jsnice.org/](http://www.jsnice.org/)

[https://tio.run/#javascript-babel-node](https://tio.run/#javascript-babel-node)

## DOM

Here is what we will be covering in the DOM section (keep in mind that these are just a few lines of code, DOM manipulation is a vast subject):

{% code overflow="wrap" %}
```javascript
document.getElementByID('Name_of_ID'); // Grabs the element with the ID name from the connected HTML 
filedocument.getElementByClassName('Name_of_Class'); // Grabs the element with the class name from the connected HTML 
filedocument.getElementByTagName('Name_of_Tag'); // Grabs a specific tag name from the connected HTML file
```
{% endcode %}

There are also methods we can use to access different things within our HTML files such as addEventListener, removeEventListener, and many more. Most of what the DOM does is change, replace, edit, or in some form, manipulate the HTML file or webpage that you're working on. For us to successfully manipulate the DOM, we use events. These events are added to HTML tags to work with our JavaScript file. Some of the more important events that are used a lot, you can find here:

* **onclick**: Activates when a user clicks on the specific element
* **onmouseover**: Activates when a user hovers over a specific element
* **onload**: Activates when the element has loaded
* and many more that are used. You can find a complete list here: [https://www.w3schools.com/js/js\_htmldom\_events.asp](https://www.w3schools.com/js/js_htmldom_events.asp)

Code example:

![](https://raw.githubusercontent.com/GhostlyPy/javascriptbasics/master/DOM_POP.png)

Now when a user clicks on the **Click Me** button, an alert pops up that says **POP!!!**

The Document Object Model (DOM) has a ton of resources, and combining that with CSS will help your webpage **POP**. Eventually, if you take on web development or front-end programming, then you'll not only gain knowledge around the DOM, but you'll be able to manipulate a virtual DOM using React, cut your code in half using jQuery, and even combine your skills with PHP or Nodejs files for server manipulation. Good luck with your continued journey to learn JavaScript, and remember it can do so much more than just create webpages and add interactiveness.

## References

Since we only touched on the very basics, here are some free resources to continue learning JavaScript:

1. [https://developer.mozilla.org/en-US/docs/Web/JavaScript](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
2. [https://www.w3schools.com/js/default.asp](https://www.w3schools.com/js/default.asp)

## What wasn't covered:

* Libraries or Frameworks
* ES6 Destructuring
* Advanced Methods
* And so much more!
