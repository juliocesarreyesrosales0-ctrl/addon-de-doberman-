package com.doberman.antivirus

import android.app.Application
import com.doberman.antivirus.guard.Notifier
import com.doberman.antivirus.guard.SpamRepository

class DobermanApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Notifier.createChannels(this)
        SpamRepository.init(this)
    }
}
