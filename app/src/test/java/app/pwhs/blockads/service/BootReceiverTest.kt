package app.pwhs.blockads.service

import app.pwhs.blockads.data.datastore.AppPreferences
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BootReceiverTest {
    @Test
    fun rootModeStartsAfterUnlockWhenAutoReconnectIsEnabled() {
        assertTrue(shouldAutoStartAfterBoot(true, false, AppPreferences.ROUTING_MODE_ROOT, false))
        assertFalse(shouldAutoStartAfterBoot(true, false, AppPreferences.ROUTING_MODE_ROOT, true))
        assertFalse(shouldAutoStartAfterBoot(false, true, AppPreferences.ROUTING_MODE_ROOT, false))
    }

    @Test
    fun vpnModeRetainsPreviousEnablementRule() {
        assertTrue(shouldAutoStartAfterBoot(true, true, AppPreferences.ROUTING_MODE_DIRECT, false))
        assertFalse(shouldAutoStartAfterBoot(true, false, AppPreferences.ROUTING_MODE_DIRECT, false))
    }
}
