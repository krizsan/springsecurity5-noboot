package se.ivankrizsan.spring.web;

import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Date;

/**
 * Simple controller that generates a greeting string.
 * The controller is not annotated with @Controller and thus a Spring bean need to
 * be explicitly created.
 *
 * @author Ivan Krizsan
 * @see WebConfiguration
 */
@RequestMapping("/hello")
public class HelloController {
    @ResponseBody
    @GetMapping
    public String printHello(final ModelMap model) {
        final Date theDate = new Date();
        return "Hello Java-configured web application, the time is now " + theDate;
    }
}
