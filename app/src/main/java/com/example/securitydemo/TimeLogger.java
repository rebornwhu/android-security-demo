package com.example.securitydemo;

import android.util.Log;

public class TimeLogger {

    private static final String TAG = "time_pbkdf";

    private long startTime;

    public TimeLogger() {
        startTime = System.currentTimeMillis();
    }

    public void start() {
        startTime = System.currentTimeMillis();
    }

    public void end(String messagePrefix) {
        long endTime = System.currentTimeMillis();
        Log.i(TAG, messagePrefix + ": " + (endTime-startTime));
    }
}
