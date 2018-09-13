<%@ taglib prefix="c" uri="http://www.springframework.org/tags" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
    <head>
        <title>Spring Security 5 without using SpringBoot</title>
    </head>
    <body>
        <p>This is the Main Page.</p>
        <p>
            <a href="${pageContext.request.contextPath}/logout">Logout</a>
        </p>
        <p>
            <a href="hello">Get a Greeting from a web controller</a>
        </p>
        <p>
            <a href="static/test.html">Static contents: test.html</a>
        </p>
    </body>
</html>
