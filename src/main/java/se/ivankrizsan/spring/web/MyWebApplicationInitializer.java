package se.ivankrizsan.spring.web;

import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

import javax.servlet.Filter;

/**
 * Web application initializer specifies the configuration files that will make up
 *  the root application Spring context.
 *  In addition this is the place where the servlet filters to be added and mapped
 *  to the dispatcher servlet.
 */
public class MyWebApplicationInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {
    /* Constant(s): */
    public static final String SPRINGSECURITY_FILTERCHAINPROXY_BEANNAME = "springSecurityFilterChain";


    @Override
    protected Filter[] getServletFilters() {
        return new Filter[] { new DelegatingFilterProxy(SPRINGSECURITY_FILTERCHAINPROXY_BEANNAME) };
    }

    /**
     * Retrieves list of configuration classes which are to be used to create the root application
     * context in the web application.
     *
     * @return Spring Java configuration classes to be used when creating root application context.
     */
    @Override
    protected Class<?>[] getRootConfigClasses() {
        return new Class[] { WebConfiguration.class, WebSecurityConfiguration.class };
    }

    /**
     * Retrieves list of configuration classes which are to be used to create the servlet application
     * context.
     *
     * @return Returns null, since all beans will be located in the root application context.
     */
    @Override
    protected Class<?>[] getServletConfigClasses() {
        return null;
    }

    @Override
    protected String[] getServletMappings() {
        return new String[] { "/" };
    }
}
