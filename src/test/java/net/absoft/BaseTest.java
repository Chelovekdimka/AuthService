package net.absoft;

import net.absoft.services.AuthenticationService;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;

public class BaseTest {
    @BeforeMethod
    public void baseSetUp() {
        System.out.println("Base Setup");
    }
    @AfterMethod
    public void tearDown() {
        System.out.println("Base tear down");
    }
}

