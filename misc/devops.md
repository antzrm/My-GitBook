# DevOps



## C\#

{% code fullWidth="false" %}
```csharp
namespace DemoOnly
{
    internal class BasicProgramming
    {
        static void Main(string[] args)
        {
            string to_print = "Hello World!";
            ShowOutput(to_print);
        }

        public static void ShowOutput(string text)
        {
            // prints the contents of the text variable
            Console.WriteLine(text);
        }
    }
}
```
{% endcode %}

<table data-full-width="true"><thead><tr><th>Code Syntax</th><th>Details</th></tr></thead><tbody><tr><td>Namespace</td><td>A container that organises related code elements, such as classes, into a logical grouping. It helps prevent naming conflicts and provides structure to the code. In this example, the namespace DemoOnly is the namespace that contains the BasicProgramming class.</td></tr><tr><td>Class</td><td>Defines the structure and behaviour (through functions or methods) of the objects it contains. In this example, BasicProgramming is a class that includes the Main function and the ShowOutput function. Moreover, the Main function is the program's entry point, where the program starts its execution.</td></tr><tr><td>Function</td><td>A reusable block of code that performs a specific task or action. In this example, the ShowOutput function takes a string (through the text argument) as an input and uses it on Console.WriteLine to print it as its output. Note that the ShowOutput function only receives one argument based on how it is written.</td></tr><tr><td>Variable</td><td>A named storage location that can hold data, such as numbers (integers), text (strings), or objects. In this example, to_print is a variable that handles the text: "Hello World!"</td></tr></tbody></table>



### Importing modules

C# uses the `using` directive to include namespaces and access classes and functions from external libraries.

`using System;`

`// after importing, we can now use all the classes and functions available from the System namespace`The code snippet above loads an external namespace called `System`. This means that this code can now use everything inside the System namespace.

## PPE (Poisoned Pipeline Execution)

[https://medium.com/cider-sec/ppe-poisoned-pipeline-execution-34f4e8d0d4e9](https://medium.com/cider-sec/ppe-poisoned-pipeline-execution-34f4e8d0d4e9)

If you can modify a repo with a Makefile, git clone, modify the Makefile add commands to isue, git add, git clone, git push and then build the repo to achieve RCE.
