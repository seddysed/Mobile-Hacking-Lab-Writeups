# Mobile Hacking Lab — Config Editor RCE

## Overview

This lab demonstrates remote code execution (RCE) caused by unsafe YAML deserialization. The Config Editor application loads user-supplied YAML with SnakeYAML and allows YAML global tags to instantiate classes available in the application's classpath.

## Objective

Identify the vulnerable YAML parsing behavior, create a safe proof of concept, and verify command execution within the target application's sandbox.

## Methodology

1. Decompiled and reviewed the application using JADX.
2. Identified the `LegacyCommandUtil` class.
3. Confirmed that its constructor passes user-controlled input to `Runtime.getRuntime().exec()`.
4. Created a YAML document that referenced the class through a global YAML tag.
5. Loaded the YAML file through the app's import functionality.
6. Verified execution by confirming creation of a file in the application's private storage directory.

## Vulnerability

The vulnerable class was:

```java
com.mobilehackinglab.configeditor.LegacyCommandUtil
```

Its constructor executed a supplied system command:

```java
Runtime.getRuntime().exec(command);
```

Because SnakeYAML was configured unsafely, the YAML parser could instantiate this class through reflection. This meant that loading a crafted YAML file resulted in the equivalent of:

```java
new LegacyCommandUtil("<controlled command>");
```

## Proof of Concept

A YAML payload referenced `LegacyCommandUtil` and supplied a benign `touch` command as its constructor argument. When the file was loaded, the command created a proof-of-concept file in the application’s private `files` directory.

I verified the result with:

```bash
adb shell "run-as com.mobilehackinglab.configeditor ls -l files"
```

The presence of the proof-of-concept file confirmed RCE in the context of the Config Editor application.

## Impact

An attacker able to convince a user to load a malicious YAML file could execute commands with the permissions of `com.mobilehackinglab.configeditor`. The impact is limited to the target application's Android sandbox, but could still expose or modify data accessible to that app.

## Root Cause

The issue was caused by deserializing untrusted YAML with an unrestricted SnakeYAML constructor. Unsafe YAML deserialization can allow attacker-controlled type tags to create arbitrary Java objects, including classes with dangerous constructors or setters.

## Remediation

- Upgrade to a current SnakeYAML version.
- Use `SafeConstructor` or restrictive tag handling for untrusted YAML.
- Deserialize only expected primitive values, lists, maps, or explicitly approved data models.
- Avoid command execution in constructors, setters, or deserialization paths.
- Validate imported configuration files before parsing them.

## Tools Used

- Android Studio Emulator / Nox
- JADX
- ADB
- SnakeYAML
- Mobile Hacking Lab

## Skills Demonstrated

- Android static analysis
- Java/Kotlin code review
- Insecure deserialization analysis
- YAML parser exploitation in a controlled lab
- Android application sandbox verification
- Security remediation planning
