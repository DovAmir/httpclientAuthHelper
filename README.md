# android-ntlm
## What is it?
Android NTLM Authentication

## How to use?
* Use as submodule
```
git submodule add git@github.com:masconsult/android-ntlm.git
```
* Add android-ntlm as library into your project (Properties/Android/Library/Add)
* Register AuthSheme and specify NTCredentials

Example:
```
    DefaultHttpClient httpclient = new DefaultHttpClient();
    // register ntlm auth scheme
    httpclient.getAuthSchemes().register("ntlm", new NTLMSchemeFactory());
    httpclient.getCredentialsProvider().setCredentials(
    		// Limit the credentials only to the specified domain and port
            new AuthScope("masconsult.eu", -1),
            // Specify credentials, most of the time only user/pass is needed
            new NTCredentials(username, password, "", "")
            );
```

## How to configure Proguard?
Just add these lines
```
-dontwarn javax.servlet.**
-dontwarn jcifs.http.NetworkExplorer
```

## Credits
* Based on article http://www.tekritisoftware.com/android-ntlm-authentication
* Uses jcifs from SAMBA project

## License

    Copyright 2012 MASConsult Ltd.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.


