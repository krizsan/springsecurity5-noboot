package se.ivankrizsan.spring.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Spring web configuration excluding web security configuration, which is located in a separate class.
 *
 * @author Ivan Krizsan
 */
@EnableWebMvc
@Configuration
public class WebConfiguration implements WebMvcConfigurer {
    /* Constant(s): */
    public static final String STATIC_WEBRESOURCES_PATHPATTERN = "/static/**";
    public static final String STATIC_WEBRESOURCES_LOCATION = "/static/";

    /* Dependencies: */
    @Autowired
    protected ApplicationContext applicationContext;

    @Bean
    public HelloController helloController() {
        return new HelloController();
    }

    /**
     * Adds resource handlers to supplied resource handler registry.
     * In this example a resource handler is added in order to serve static contents
     * located in the webapp/static directory.
     *
     * @param inResourceHandlerRegistry Registry to register new resource handlers in.
     */
    @Override
    public void addResourceHandlers(final ResourceHandlerRegistry inResourceHandlerRegistry) {
        inResourceHandlerRegistry
            .addResourceHandler(STATIC_WEBRESOURCES_PATHPATTERN)
            .addResourceLocations(STATIC_WEBRESOURCES_LOCATION)
            .setCachePeriod(0);
    }
}
