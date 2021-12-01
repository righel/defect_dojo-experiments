# DefectDojo Experiments

### Installation
1. Install python deps: 
    ```
    pip install -r requirements.txt
    ```

2. Have [django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) running, [docker install is recommended](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md).


## dojo-endpoints.py
1. Get Products via DefectDojo API
2. Get active Endpoints via nmap|shodan|censys|nuclei|custom
3. Push Endpoints to DefectDojo API

```
$ python3 dojo-endpoints.py --cpe cpe:2.3:a:microsoft:exchange_server
INFO: Searching for products matching cpe: cpe:2.3:a:microsoft:exchange_server
INFO: Product: cpe:2.3:a:microsoft:exchange_server
DEBUG: [Shodan] Searching for endpoints with query: http.title:outlook exchange country:"LU"
DEBUG: Adding 29 endpoints to product id=3 ...
DEBUG: Endpoints added to DefectDojo.
```

## dojo-scanner.py
1. Get active Engagements
2. Get Engagement Preset*
3. Get target Endpoints
4. Run the appropiate scan for the given Engagement Preset
5. Push the Scan Report to DefectDojo

```
$ python3 dojo-scanner.py 
INFO: Processing engagement: ms-exchange-version-nse ...
INFO: Running engagement preset: ms_exchange_version_nse ...
DEBUG: Update engagement id=35 status to In Progress
DEBUG: Running custom preset /REDACTED/ms_exchange_version_nse.py ...
DEBUG: Running nmap command: nmap -v0 --script /REDACTED/ms-exchange-version.nse -p 7800 -oX /REDACTED/output/127.0.0.1_7800.xml 127.0.0.1
INFO: Scan report pushed, created test id=63.
DEBUG: Running nmap command: nmap -v0 --script /REDACTED/ms-exchange-version.nse -p 7800 -oX /REDACTED/output/localhost_7800.xml localhost
INFO: Scan report pushed, created test id=64.
```

**NOTE**: Engagements only allow 1 Preset and are tied to a specific Product, this is not very convenient as one type of scan could be used for different product families. Maybe we could use the `test_strategy` property (URL) and define a JSON schema for the tests to be run for an Engagement (which could be many).