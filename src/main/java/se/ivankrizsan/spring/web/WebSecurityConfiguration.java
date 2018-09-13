package se.ivankrizsan.spring.web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.debug.DebugFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;

import static se.ivankrizsan.spring.web.MyWebApplicationInitializer.SPRINGSECURITY_FILTERCHAINPROXY_BEANNAME;

/**
 * Spring Security configuration for a Java web application that does not use Spring Boot.
 * This configuration has deliberately been written as to expose all the details of
 * configuring Spring Security in a web application.
 * This is not an example of how you would want to configure Spring Security in your
 * web application.
 *
 * @author Ivan Krizsan
 */
@Configuration
@EnableWebSecurity(debug = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
    /* Constant(s): */
    /** Relative URL to custom login web-page. */
    public static final String LOGIN_PAGE_URL = "/static/login.html";
    /**
     * Relative URL to which form on login web-page will be POSTed when user attempts to log in.
     * Note the relationship to the above login web-page URL.
     */
    public static final String LOGIN_PAGE_POST_URL = "/static/login";
    /** Relative URL to which user will be directed after having logged out. */
    public static final String LOGOUT_SUCCESS_URL = "/index.jsp";
    /** Name of user that can log in to the example application. */
    public static final String USER_ADMIN_NAME = "admin";
    /** Password of user that can log in to the example application. */
    public static final String USER_ADMIN_PASSWORD = "secret";

    /**
     * Default constructor.
     * Disables default configuration since I want to show all the details of
     * a Java-based Spring Security configuration in a web application that does not
     * use Spring Boot.
     */
    public WebSecurityConfiguration() {
        super(true);
    }

    /**
     * Creates the Spring Security filter chain proxy bean configured with the supplied HTTP
     * firewall and the supplied security filters.
     * Note that the name of this bean must match the name supplied to the delegating
     * filter proxy created in the web application initializer.
     *
     * @param inHttpFirewall HTTP firewall with application-specific configuration.
     * @param inFilterSecurityInterceptor Responsible for security handling of HTTP resources.
     * @param inExceptionTranslationFilter Translates security-related exceptions to HTTP responses
     * and handles redirection to login page.
     * @param inSecurityContextPersistenceFilter Create and populate the security context.
     * @param inLogoutFilter Handles user log out.
     * @return Spring Security filter chain proxy bean.
     * @see MyWebApplicationInitializer
     */
    @Bean(name = SPRINGSECURITY_FILTERCHAINPROXY_BEANNAME)
    public Filter springSecurityFilterChain(
        final HttpFirewall inHttpFirewall,
        final FilterSecurityInterceptor inFilterSecurityInterceptor,
        final ExceptionTranslationFilter inExceptionTranslationFilter,
        final SecurityContextPersistenceFilter inSecurityContextPersistenceFilter,
        final UsernamePasswordAuthenticationFilter inUsernamePasswordAuthenticationFilter,
        final LogoutFilter inLogoutFilter) {

        /* Create the default filter chain that allow only logged in user to access pages in the application. */
        final MvcRequestMatcher theDefaultRequestMatcher = new MvcRequestMatcher(
            new HandlerMappingIntrospector(),
            "/**");
        final DefaultSecurityFilterChain theDefaultSecurityFilterChain = new DefaultSecurityFilterChain(
            theDefaultRequestMatcher,
            /* Filters start here. */
            inSecurityContextPersistenceFilter,
            inLogoutFilter,
            inUsernamePasswordAuthenticationFilter,
            inExceptionTranslationFilter,
            inFilterSecurityInterceptor);

        /* Create the security filter chain that allows anyone access to the login page. */
        final MvcRequestMatcher theLoginRequestMatcher = new MvcRequestMatcher(
            new HandlerMappingIntrospector(),
            LOGIN_PAGE_URL);
        final DefaultSecurityFilterChain theLoginSecurityFilterChain = new DefaultSecurityFilterChain(
            theLoginRequestMatcher);

        /*
         * Create the filter chain proxy with both the filter chains created above.
         * Note that the ordering of the filter chains in the list supplied to the
         * constructor of {@code FilterChainProxy} is significant:
         * The security filter chain allowing for access to the login page must be
         * placed before the default security filter chain, or else access to the
         * login page will not be allowed when a user needs to login.
         */
        final FilterChainProxy theFilterChainProxy = new FilterChainProxy(
            Arrays.asList(theLoginSecurityFilterChain, theDefaultSecurityFilterChain)
        );
        /*
         * Set the customized HTTP firewall on the filter chain proxy.
         * See {@link #customHttpFirewall} for details.
         */
        theFilterChainProxy.setFirewall(inHttpFirewall);

        /* Wrap the filter chain proxy in a debug filter as to get additional debug log. */
        final DebugFilter theDebugFilter = new DebugFilter(theFilterChainProxy);
        return theDebugFilter;
    }

    /**
     * Creates the logout filter bean that will invoke a set of logout handlers
     * when a user wants to log out and, upon successful logout, redirect to the
     * main application page.
     *
     * @return Logout filter.
     */
    @Bean
    public LogoutFilter logoutFilter() {
        /*
         * Create the list of logout handlers that are to be run when user logs out.
         * The {@code SecurityContextLogoutHandler} invalidates the HTTP session and
         * clears the current authentication from the security context.
         * The {@code CookieClearingLogoutHandler} clears cookies upon logout.
         * In this example, the JSESSIONID cookie will be cleared.
         */
        final List<LogoutHandler> theLogoutHandlers = new ArrayList<>();
        theLogoutHandlers.add(new SecurityContextLogoutHandler());
        theLogoutHandlers.add(new CookieClearingLogoutHandler("JSESSIONID"));

        /*
         * The logout filter only allows for one single logout handler to be configured,
         * so a {@code CompositeLogoutHandler} is created that will iterate over
         * the logout handlers in the supplied list.
         */
        final CompositeLogoutHandler theCompositeLogoutHandler =
            new CompositeLogoutHandler(theLogoutHandlers);

        /*
         * Create the logout filter that invokes the supplied logout handler when a user
         * logs out and, upon successful logout, redirects to the supplied URL.
         * In this example the user will be redirected to the main page (index.jsp).
         */
        return new LogoutFilter(LOGOUT_SUCCESS_URL, theCompositeLogoutHandler);
    }

    /**
     * Security context persistence filter bean responsible for retrieving information from
     * a security context repository and storing it in the security context prior to a request
     * and then store the information in the repository once the request has completed.
     * Uses the default {@link HttpSessionSecurityContextRepository} to store the security context.
     *
     * @return Security context persistence filter bean.
     */
    @Bean
    public SecurityContextPersistenceFilter securityContextPersistenceFilter() {
        final SecurityContextPersistenceFilter theSecurityContextPersistenceFilter =
            new SecurityContextPersistenceFilter();
        theSecurityContextPersistenceFilter.setForceEagerSessionCreation(true);
        return theSecurityContextPersistenceFilter;
    }

    /**
     * Exception translation filter bean that translates security-related
     * exceptions to HTTP responses.
     * The login page URL is configured on the exception translation filter, as to
     * ensure redirection to the login page in the case where the user is unauthorized
     * to view a resource.
     *
     * @return Exception translation filter bean.
     */
    @Bean
    public ExceptionTranslationFilter exceptionTranslationFilter() {
        final LoginUrlAuthenticationEntryPoint theLoginUrlAuthenticationEntryPoint =
            new LoginUrlAuthenticationEntryPoint(LOGIN_PAGE_URL);

        return new ExceptionTranslationFilter(theLoginUrlAuthenticationEntryPoint);
    }

    /**
     * Filter security interceptor bean responsible for handling security of HTTP resources
     * using the supplied authentication and access decision managers.
     *
     * @param inAuthenticationManager Authenticates users.
     * @param inAccessDecisionManager Determines whether access to HTTP resource is allowed or not.
     * @return Filter security interceptor bean.
     */
    @Bean
    public FilterSecurityInterceptor filterSecurityInterceptor(
        final AuthenticationManager inAuthenticationManager,
        final AccessDecisionManager inAccessDecisionManager) {

        /*
         * Create the security metadata source which contains mappings between web
         * resource URL patterns and, for each URL pattern, one or more security
         * configurations specifying what is required to access the resource(s)
         * behind the URL pattern.
         * Note that the ordering of these mappings is significant and should be
         * specific to general.
         */
        final LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> theRequestMap =
            new LinkedHashMap<>();
        /* Allow users with the role ADMIN to access anything in the web application. */
        theRequestMap.put(new AntPathRequestMatcher("/**"),
            Collections.singleton(new SecurityConfig("ROLE_ADMIN")));
        final DefaultFilterInvocationSecurityMetadataSource theSecurityMetadataSource =
            new DefaultFilterInvocationSecurityMetadataSource(theRequestMap);

        /* Create and configure the filter security interceptor. */
        final FilterSecurityInterceptor theFilterSecurityInterceptor = new FilterSecurityInterceptor();
        theFilterSecurityInterceptor.setAuthenticationManager(inAuthenticationManager);
        theFilterSecurityInterceptor.setSecurityMetadataSource(theSecurityMetadataSource);

        theFilterSecurityInterceptor.setAccessDecisionManager(inAccessDecisionManager);

        return theFilterSecurityInterceptor;
    }

    /**
     * Access decision manager bean responsible for making access control decisions.
     *
     * @return Access decision manager bean.
     */
    @Bean AccessDecisionManager accessDecisionManager() {
        final List<AccessDecisionVoter<?>> theAccessDecisionVoters = Arrays.asList(
            new AuthenticatedVoter(),
            new RoleVoter(),
            new WebExpressionVoter());

        return new AffirmativeBased(theAccessDecisionVoters);
    }

    /**
     * User name and password authentication filter bean that allows users to authenticate
     * using a login page and the supplied authentication manager.
     * This authentication filter allows session creation.
     *
     * @param inAuthenticationManager Authenticates users.
     * @return User name and password authentication filter bean.
     */
    @Bean
    public UsernamePasswordAuthenticationFilter usernamePasswordAuthenicationFilter(
        final AuthenticationManager inAuthenticationManager) {
        final UsernamePasswordAuthenticationFilter theUsernamePasswordAuthenticationFilter =
            new UsernamePasswordAuthenticationFilter();
        theUsernamePasswordAuthenticationFilter.setAuthenticationManager(inAuthenticationManager);
        theUsernamePasswordAuthenticationFilter.setAllowSessionCreation(true);
        /*
         * Set the URL which should be intercepted as a login attempt by the username-password
         * authentication filter.
         * The default is a POST request to /login but since I have placed the login page
         * in the file webapp/static/login.html, the POST request will be made to
         * /static/login instead of just /login.
         */
        theUsernamePasswordAuthenticationFilter.setRequiresAuthenticationRequestMatcher(
            new AntPathRequestMatcher(LOGIN_PAGE_POST_URL, HttpMethod.POST.name()));

        return theUsernamePasswordAuthenticationFilter;
    }

    /**
     * Creates an authentication manager responsible for authenticating users.
     * An authentication manager delegates user authentication to one or more authentication providers.
     * In this example, only one single authentication provider is used.
     *
     * @param inAuthenticationProvider Authentication provider that authentication manager will delegate
     * user authentication to.
     * @return Authentication manager bean.
     */
    @Bean
    public AuthenticationManager authenticationManager(final AuthenticationProvider inAuthenticationProvider) {
        return new ProviderManager(Collections.singletonList(inAuthenticationProvider));
    }

    /**
     * Creates the authentication provider responsible for authenticating users.
     * Retrieves user information from the supplied user details service.
     *
     * @param inUserDetailsService Service from which to retrieve user information.
     * @return Authentication provider bean.
     */
    @Bean
    public AuthenticationProvider authenticationProvider(final UserDetailsService inUserDetailsService) {
        final DaoAuthenticationProvider theAuthenticationProvider = new DaoAuthenticationProvider();
        theAuthenticationProvider.setUserDetailsService(inUserDetailsService);

        /*
         * Use the no-op password encoder, since we do not care about passwords being in
         * plaintext in this example program. This is of course not recommended in a
         * production environment.
         */
        theAuthenticationProvider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
        return theAuthenticationProvider;
    }

    /**
     * Creates the user details service responsible for reading user information into memory.
     * In this particular example an {@code InMemoryUserDetailsManager} is used that retains
     * all user data in memory only.
     *
     * @return User details service bean.
     */
    @Override
    @Bean
    public UserDetailsService userDetailsService() {
        /* User information only stored in memory. */
        final InMemoryUserDetailsManager theUserDetailsManager = new InMemoryUserDetailsManager();

        /*
         * Create a user "admin" with the password "secret" in the "ADMIN" role.
         * Note that the role name must be prefixed with "ROLE_".
         */
        final SimpleGrantedAuthority theGrantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
        final UserDetails theUserDetails =
            new User(USER_ADMIN_NAME, USER_ADMIN_PASSWORD, Collections.singleton(theGrantedAuthority));

        /* Add the new user to the user details manager. */
        theUserDetailsManager.createUser(theUserDetails);

        return theUserDetailsManager;
    }

    /**
     * Creates a slightly relaxed version of the {@code StrictHttpFirewall} that allows
     * using semicolon in URLs, which Spring MVC normally does not.
     * With Spring Boot, creating this bean is enough and no further configuration is needed.
     * When not using Spring Boot, the custom HTTP firewall must be set on the {@code FilterChainProxy},
     * as can be seen in the method
     * {@link #springSecurityFilterChain(HttpFirewall, FilterSecurityInterceptor, ExceptionTranslationFilter, SecurityContextPersistenceFilter, UsernamePasswordAuthenticationFilter, LogoutFilter)}
     *
     * @return Slightly relaxed instance of the {@code StrictHttpFirewall}.
     */
    @Bean
    public HttpFirewall customHttpFirewall() {
        final StrictHttpFirewall theHttpFirewall = new StrictHttpFirewall();
        theHttpFirewall.setAllowSemicolon(true);
        return theHttpFirewall;
    }
}
