package net.absoft;

import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.sun.net.httpserver.Authenticator;
import net.absoft.data.Response;
import net.absoft.services.AuthenticationService;
import org.testng.IRetryAnalyzer;
import org.testng.annotations.*;
import org.testng.asserts.SoftAssert;

import static org.testng.Assert.*;

public class AuthenticationServiceTest extends BaseTest{
private AuthenticationService authenticationService;
private String message;


  @BeforeMethod (alwaysRun = true)
  public void setUp() {
    authenticationService = new AuthenticationService();
    System.out.println("setup");
  }

  @AfterMethod
  public void tearDown() {
    System.out.println("teardown");
  }

  @Test(
          groups = "negative"
  )
  public void testSample() throws InterruptedException {
    Thread.sleep(2000);
    System.out.println("test Sample: " + new Date());
    fail("FAILING TEST");
  }


  @Test (
          description = "Test Successful Authentication",
          groups = "positive"
  )
  public void testSuccessfulAuthentication() {
    Response response = authenticationService.authenticate("user1@test.com", "password1");
    assertEquals(response.getCode(), 200, "Response code should be 200");
    assertTrue(validateToken(response.getMessage()),
        "Token should be the 32 digits string. Got: " + response.getMessage());
  }

  @DataProvider(name = "invalidLogins", parallel = true)
  public Object [][] invalidLogins() {
    return new Object[][] {
            new Object[]{"user1@test.com", "wrong_password1", new Response(401,"Invalid email or password")},
            new Object[]{"", "password1", new Response(400,"Email should not be empty string")},
            new Object[]{"user1", "password1", new Response(400,"Invalid email")},
            new Object[]{"user1", "", new Response(400,"Password should not be empty string")}
    };
  }


@Test (
        groups = "negative",
        dataProvider = "invalidLogins"
)
  public void testInvalidAuthentication(String email, String password, Response expectedResponse) {
    Response response = authenticationService
            .authenticate("user1@test", "wrong_password1");
    assertEquals(response.getCode(), 401, "Response code should be 401");
    assertEquals(response.getMessage(), "Invalid email or password",
            "Response message should be \"Password should not be empty string\"");
  }



//  @Test (
//          description = "Test Authentication With Wrong Password",
//          groups = "negative"
//  )
//  public void testAuthenticationWithWrongPassword() {
//    validateErrorResponse(
//            new AuthenticationService().authenticate("user1@test.com", "wrong_password1"),
//            401, "Invalid email or password"
//    );
//  }
//
//  private void validateErrorResponse(Response response, int code, String message) {
//    SoftAssert sa = new SoftAssert();
//    sa.assertEquals(response.getCode(), code, "Response code should be 401");
//    sa.assertEquals(response.getMessage(), message,
//            "BROKEN Invalid email or password");
//    sa.assertAll();
//  }

//  @Test (
//          description = "Test Authentication With Empty Email",
//          groups = "negative")
//  public void testAuthenticationWithEmptyEmail() {
//    Response expectedResponse = new Response(400, "Email should not be empty string");
//    Response actualResponse = new AuthenticationService().authenticate("", "password1");
//    assertEquals(actualResponse, expectedResponse, "Unexpected response");
//  }

//  @Test (
//          description = "Test Authentication With Invalid Email",
//          groups = "negative")
//  public void testAuthenticationWithInvalidEmail() {
//    Response response = new AuthenticationService().authenticate("user1", "password1");
//    assertEquals(response.getCode(), 400, "Response code should be 200");
//    assertEquals(response.getMessage(), "Invalid email",
//        "Response message should be \"Invalid email\"");
//  }
//
//  @Test (description = "Test Authentication With Empty Password",
//          groups = "negative"
//  )
//  public void testAuthenticationWithEmptyPassword() {
//    Response response = new AuthenticationService().authenticate("user1@test", "");
//    assertEquals(response.getCode(), 400, "Response code should be 400");
//    assertEquals(response.getMessage(), "Password should not be empty string",
//        "Response message should be \"Password should not be empty string\"");
//  }

  private boolean validateToken(String token) {
    final Pattern pattern = Pattern.compile("\\S{32}", Pattern.MULTILINE);
    final Matcher matcher = pattern.matcher(token);
    return matcher.matches();
  }
}
