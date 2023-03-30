# IDA Plugin

Plugin for interfacing Cythereal MAGIC with IDA — Interactive Disassembler

After performing the installation instructions, the plugin should load automatically in IDA. Access it through the menus at the top **"Edit -> Plugins -> MAGIC"** or by the shortcut **"ctrl+shift+A"**.

## Features
- **`PLACEHOLDER`**

## Built and Verified for
This does not mean it won't work for other versions, but there are no guarantees yet. This should be able to work with Windows installations as long as it's kept in mind that this guide is currently written for Linux.
- IDA Pro 8.2 (64-bit)
- IDAPython 64-bit v7.4.0
- Python 3.6.9
- Ubuntu 18.04.6 LTS

## Prerequisites
There are few prerequisites, the `requirements.txt` is addressed in the next section.

- Install IDApro — This should automatically include IDAPython

## Installation
- Move the plugin script `MAGIC_widget.py` to `idapro/plugins`
- Copy the contents of `.env.example` to a file called `.env` and place it in the `idapro/plugins` directory
    * If you are not a developer, you should only need to change `MAGIC_API_ENDPOINT` to hyperlink to MAGIC API's main entrypoint and `MAGIC_API_KEY` to your MAGIC API key
    * In case you are a developer, read the [environment variables](#environment-variables) section and change them accordingly
- For developers it is recommended to use a virtual environment for consistency
    * This requires extra configuration, ***You should ignore the rest of this section and skip to [Development Setup](#development-setup)***
    * Otherwise, you can ignore the development section
- Install requirements using `pip install -r requirements.txt` on the version of python used by IDA
    * This should be the default installed version, but make sure in case issues come up
    * To do this, install a simple python library which is not included in the default python installation [such as "art"](https://pypi.org/project/art/) into your target environment
    * If you can import and run the library through IDA's CLI for python, then IDA is using the correct environment

## Development Setup
- Create a virtual environment and note the bin path `yourvenv/bin/`
- Run `source yourvenv/bin/activate` to launch the virtual environment
    * Note that required dependancies should be installed within the virtual environment
    * When working with IDA, this is usually the only reason to manually launch the virtual environment
- With the virtual environment active, run `pip install -r requirements.txt`
    * To ensure that IDA is running off of the correct environment, install a simple python library which is not included in the default python installation [such as "art"](https://pypi.org/project/art/) into your target environment
    * If you can import and run the library through IDA's CLI for python, then IDA is using the correct environment
- You can type `deactivate` in the terminal to exit the virtual environment at this step
- In `idapro/python/examples/core` there is a script `idapythonrc.py`
    * Append the code in the following collapsible to `idapythonrc.py`
        * This will execute a script activating the virtual environment that IDA will use
        
        contents to add to `idapythonrc.py`:
        ```python
        import os
        virtualenv_path = "path/to/your/virtual/environment"

        def activate_virtualenv(virtualenv_path):
        for bindir in ("Scripts", "bin"):
            activate_this_path = os.path.join(virtualenv_path, bindir, "activate_this.py")
            if os.path.exists(activate_this_path):
                break
        else:
            raise ValueError('Could not find "activate_this.py" in ' + virtualenv_path)

        with open(activate_this_path) as f:
            exec(f.read(), dict(__file__=activate_this_path))

        activate_virtualenv(os.path.join(idaapi.get_user_idadir(), virtualenv_path))
        ```

    * Move this script inside `~/.idapro/`
        * Placing it here means IDA will run this code directly after core initialization
- This code requires a script in the virtual environment bin that is deprecated in later versions of `python -m venv` 
    * Create a file in `yourvenv/bin` called `activate_this.py`
    * Appending the code in the following collapsible essentially tells the running application (IDA in this case) to prepend the virtual environment to its PATH, thereby prioritizing that python environment

        contents of `activate_this.py`:
        ```python
        """By using execfile(this_file, dict(__file__=this_file)) you will
        activate this virtualenv environment.
        This can be used when you must use an existing Python interpreter, not
        the virtualenv bin/python
        """
        try:
            __file__
        except NameError:
            raise AssertionError(
                "You must run this like execfile('path/to/activate_this.py', dict(__file__='path/to/activate_this.py'))")
        import sys
        import os
        old_os_path = os.environ['PATH']
        os.environ['PATH'] = os.path.dirname(os.path.abspath(__file__)) + os.pathsep + old_os_path
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if sys.platform == 'win32':
            site_packages = os.path.join(base, 'Lib', 'site-packages')
        else:
            site_packages = os.path.join(base, 'lib', 'python%s' % sys.version[:3], 'site-packages')
        prev_sys_path = list(sys.path)
        import site
        site.addsitedir(site_packages)
        sys.real_prefix = sys.prefix
        sys.prefix = base
        # Move the added items to the front of the path:
        new_sys_path = []
        for item in list(sys.path):
            if item not in prev_sys_path:
                new_sys_path.append(item)
                sys.path.remove(item)
        sys.path[:0] = new_sys_path
        ```

## Environment Variables
### MAGIC related
- MAGIC_API_ENDPOINT — str, main endpoint for sending requests to MAGIC
- MAGIC_API_CERT_PATH — str, in case requests to magic's API is unauthorized by python's requests library, we can provide the path to one of their certs
- MAGIC_API_KEY — str, API key for connecting with MAGIC's API

### state vars
- PLUGIN_DEVELOP — boolean, "True" allows the plugin to be tweaked for easier time with development. For example, in the plugin code this tells IDA to unload the plugin from memory as soon as it is finished running. This means we don't have to continually restart IDA to test plugin changes.