Python fabric ruby deployment
=============


Provision application server and deploy the Hello World Ruby Sinatra application
-------
Written configuration as code recipes in fabric python script

- Deployed the application onto a vanilla OS image (Debian wheezy)
- Used apache modpassenger to serve up the application on port 80
- Provisioned a web server with ruby to deploy the packaged Sinatra application
- Ensure that the server is locked down and secure
- Deployed and tested the hello world application



Output
-------------
- fabric python script


Fabric python script
-------------
Example: python sinatra-hello-world.py -u root -p password -P 22 192.168.10.18

    python sinatra-hello-world.py -u root -p password -P 22 puppetclient


TODO: Apache security tips
-------------
Limit requests and other directives like LimitRequestFields, LimitRequestFieldSize and LimitRequestLine

    LimitRequestBody 1048576 tRequestBody 1048576

Modify timeout

    Timeout 45

Disable support for htaccess file

    AllowOverride None

Another interesting option would be to block the download of all files that begin with .ht for example, would be as follows:

    AccessFileName .httpdoverride
    Order allow, deny Deny from all Satisfy All

Disable all options, If you want to disable the use of all options simply:
    None Options
If you only want to disable some specific, separate them with a space in policy settings:

    Options -ExecCGI -FollowSymLinks -Indexes

Do not allow apache follow symlinks

    Options -FollowSymLinks

Disables execution of CGI --> for the last bash vulnerability!

    Options -ExecCGI

Disable server-side includes

    Options -Includes

Disable directory browsing options

    Options -Indexes

Ensure that the files accessed are the desired

    Order Deny, Allow Deny from all Options None AllowOverride None
    Order Allow, Deny Allow from all

Disable any unnecessary module

    Here are some modules that are installed by default but are often not needed: mod_imap, mod_include, mod_info, mod_userdir, mod_status, mod_cgi, mod_autoindex.

