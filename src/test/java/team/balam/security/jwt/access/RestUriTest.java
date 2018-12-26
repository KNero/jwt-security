package team.balam.security.jwt.access;

import org.junit.Assert;
import org.junit.Test;

public class RestUriTest {
    @Test
    public void test1() {
        RestUri uri1 = new RestUri("/a/b/c");
        RestUri uri2 = new RestUri("/a/b/c");
        Assert.assertEquals(uri1, uri2);

        // mismatch length
        uri1 = new RestUri("/a/b/c");
        uri2 = new RestUri("/a/b/c/b");
        Assert.assertNotEquals(uri1, uri2);

        // not equals path
        uri1 = new RestUri("/a/b/c");
        uri2 = new RestUri("/a/b/b");
        Assert.assertNotEquals(uri1, uri2);

        // use wild card
        uri1 = new RestUri("/a/*/c");
        uri2 = new RestUri("/a/1/c");
        Assert.assertEquals(uri2, uri1);

        uri1 = new RestUri("/a/*/*/d");
        uri2 = new RestUri("/a/1/c/d");
        Assert.assertEquals(uri2, uri1);
    }
}
