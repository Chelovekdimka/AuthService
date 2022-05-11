package net.absoft;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.absoft.data.Response;
import net.absoft.services.AuthenticationService;
import org.testng.annotations.Test;
import org.testng.asserts.SoftAssert;

public class AuthenticationServiceTest {

  @Test
  public void testSuccessfulAuthentication() {
    Response response = new AuthenticationService().authenticate("user1@test.com", "password1");
    assertEquals(response.getCode(), 200, "Response code should be 200");
    assertTrue(validateToken(response.getMessage()),
        "Token should be the 32 digits string. Got: " + response.getMessage());
  }

  @Test
  public void testAuthenticationWithWrongPassword() {
    validateErrorResponse(
            new AuthenticationService().authenticate("user1@test.com", "wrong_password1"),
            401, "Invalid email or password"
    );
  }

  private void validateErrorResponse(Response response, int code, String message) {
    SoftAssert sa = new SoftAssert();
    sa.assertEquals(response.getCode(), code, "Response code should be 401");
    sa.assertEquals(response.getMessage(), message,
            "BROKEN Invalid email or password");
    sa.assertAll();
  }

  @Test
  public void testAuthenticationWithEmptyEmail() {
    Response expectedResponse = new Response(400, "Email should not be empty string");
    Response actualResponse = new AuthenticationService().authenticate("", "password1");
    assertEquals(actualResponse, expectedResponse, "Unexpected response");
  }

  @Test
  public void testAuthenticationWithInvalidEmail() {
    Response response = new AuthenticationService().authenticate("user1", "password1");
    assertEquals(response.getCode(), 400, "Response code should be 200");
    assertEquals(response.getMessage(), "Invalid email",
        "Response message should be \"Invalid email\"");
  }

  @Test
  public void testAuthenticationWithEmptyPassword() {
    Response response = new AuthenticationService().authenticate("user1@test", "");
    assertEquals(response.getCode(), 400, "Response code should be 400");
    assertEquals(response.getMessage(), "Password should not be empty string",
        "Response message should be \"Password should not be empty string\"");
  }

  private boolean validateToken(String token) {
    final Pattern pattern = Pattern.compile("\\S{32}", Pattern.MULTILINE);
    final Matcher matcher = pattern.matcher(token);
    return matcher.matches();
  }
}
