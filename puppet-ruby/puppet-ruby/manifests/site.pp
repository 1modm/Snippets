# tell puppet on which client to run the class
node 'puppetclient' {
    include rubygem
    include apache2
}

class apache2 {

	package { "apache2":
        	ensure => installed,
    	}

	package { "libcurl4-gnutls-dev":
        	ensure => installed,
    	}

        package { "libapache2-mod-passenger":
                ensure => installed,
        }

	service { "apache2":
    		name => $service_name,
    		ensure => running,
    		enable  => true,
    		require => Package["apache2"],
    		subscribe => File['sinatra.conf']
	}

	file { 'sinatra.conf':
		path    => '/etc/apache2/sites-enabled/sinatra.conf',
		ensure  => file,
		owner => root,
		group => root,
		mode => 664,
		require => Package['apache2'],
		source  => "puppet:///modules/apache2/sites-enabled/sinatra.conf",
		# This source file would be located on the puppet master at
		# /etc/puppet/modules/apache2/files/sites-enabled/ruby
	}

	file { 'simple-sinatra-app-master':
		path         => '/var/www/simple-sinatra-app-master',
		ensure       => directory,
		require      => Package['apache2'],
		source       => 'puppet:///modules/ruby/simple-sinatra-app-master',
		recurse      => true,
	}

}


class rubygem {
	package { "rubygems":
		ensure => installed,
	}

	package { "build-essential":
		ensure => installed,
	}

	# Ruby gems we want installed
	package { 'bundler':
		provider => 'gem',
		ensure => installed,
		require => Package[[rubygems]]
	}

	package { 'rails':
		provider => 'gem',
		ensure => installed,
		require => Package[[rubygems]]
	}

	package { 'sinatra':
		provider => 'gem',
		ensure => installed,
		require => Package[[rubygems]]
	}

	package { 'passenger':
		provider => 'gem',
		ensure => installed,
		require => Package[[rubygems]]
	}

}


