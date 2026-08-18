@{
    # Correspondance coordonnee -> produit endoflife.date.
    # Toute valeur est VALIDEE au runtime contre l'index des produits :
    # un slug inconnu est ignore (aucune donnee inventee), le composant
    # passe alors en 'product_unmapped'.
    #
    # Cles acceptees, de la plus prioritaire a la moins prioritaire :
    #   'ecosysteme:group:name'   (ex: 'maven:org.springframework.boot:spring-boot-starter')
    #   'ecosysteme:group:*'      (ex: 'maven:org.springframework.boot:*')
    #   'ecosysteme:name'         (ex: 'npm:@angular/core')
    #   'name'                    (tous ecosystemes, ex: 'openjdk')

    Exact = @{
        # --- Runtimes / plateformes ---------------------------------
        'openjdk'                  = 'java'
        'jdk'                      = 'java'
        'java'                     = 'java'
        'java-runtime'             = 'java'
        'temurin'                  = 'eclipse-temurin'
        'corretto'                 = 'amazon-corretto'
        'zulu'                     = 'azul-zulu'
        'graalvm'                  = 'graalvm'
        'node'                     = 'nodejs'
        'nodejs'                   = 'nodejs'
        'python'                   = 'python'
        'php'                      = 'php'
        'ruby'                     = 'ruby'
        'perl'                     = 'perl'
        'go'                       = 'go'
        'golang'                   = 'go'
        'dotnet'                   = 'dotnet'
        'dotnet-runtime'           = 'dotnet'
        'dotnet-sdk'               = 'dotnet'
        '.net'                     = 'dotnet'
        'netframework'             = 'dotnetfx'
        'kotlin'                   = 'kotlin'
        'scala'                    = 'scala'
        'rust'                     = 'rust'

        # --- Serveurs d'application / web --------------------------
        'tomcat'                   = 'tomcat'
        'apache-tomcat'            = 'tomcat'
        'jetty'                    = 'jetty'
        'wildfly'                  = 'wildfly'
        'jboss'                    = 'wildfly'
        'nginx'                    = 'nginx'
        'httpd'                    = 'apache'
        'apache-httpd'             = 'apache'
        'iis'                      = 'internet-explorer'   # ignore si slug absent
        'haproxy'                  = 'haproxy'
        'varnish'                  = 'varnish'

        # --- Bases de donnees / middleware -------------------------
        'postgresql'               = 'postgresql'
        'postgres'                 = 'postgresql'
        'mysql'                    = 'mysql'
        'mariadb'                  = 'mariadb'
        'mongodb'                  = 'mongodb'
        'redis'                    = 'redis'
        'elasticsearch'            = 'elasticsearch'
        'opensearch'               = 'opensearch'
        'kafka'                    = 'apache-kafka'
        'rabbitmq'                 = 'rabbitmq'
        'oracle-database'          = 'oracle-database'
        'mssql'                    = 'mssqlserver'
        'sqlserver'                = 'mssqlserver'
        'activemq'                 = 'apache-activemq'
        'cassandra'                = 'apache-cassandra'
        'solr'                     = 'apache-solr'
        'zookeeper'                = 'apache-zookeeper'

        # --- OS / conteneurs ---------------------------------------
        'ubuntu'                   = 'ubuntu'
        'debian'                   = 'debian'
        'alpine'                   = 'alpine'
        'centos'                   = 'centos'
        'rhel'                     = 'rhel'
        'redhat-enterprise-linux'  = 'rhel'
        'amazonlinux'              = 'amazon-linux'
        'windows'                  = 'windows'
        'windows-server'           = 'windows-server'
        'docker'                   = 'docker-engine'
        'kubernetes'               = 'kubernetes'

        # --- Outils / plateformes ----------------------------------
        'jenkins'                  = 'jenkins'
        'gitlab'                   = 'gitlab'
        'keycloak'                 = 'keycloak'
        'grafana'                  = 'grafana'
        'sonarqube'                = 'sonar'
        'terraform'                = 'terraform'
        'ansible'                  = 'ansible'
        'maven'                    = 'maven'
        'gradle'                   = 'gradle'

        # --- Java / Maven ------------------------------------------
        'maven:org.springframework.boot:*'      = 'spring-boot'
        'maven:org.springframework:*'           = 'spring-framework'
        'maven:org.springframework.security:*'  = 'spring-framework'
        'maven:org.springframework.cloud:*'     = 'spring-cloud'
        'maven:org.apache.tomcat:*'             = 'tomcat'
        'maven:org.apache.tomcat.embed:*'       = 'tomcat'
        'maven:org.eclipse.jetty:*'             = 'jetty'
        'maven:org.hibernate:*'                 = 'hibernate'
        'maven:org.hibernate.orm:*'             = 'hibernate'
        'maven:org.apache.struts:*'             = 'struts'
        'maven:org.apache.camel:*'              = 'apache-camel'
        'maven:org.quarkus:*'                   = 'quarkus'
        'maven:io.quarkus:*'                    = 'quarkus'
        'maven:org.jetbrains.kotlin:*'          = 'kotlin'
        'maven:org.scala-lang:*'                = 'scala'
        'maven:org.apache.kafka:*'              = 'apache-kafka'
        'maven:org.apache.solr:*'               = 'apache-solr'
        'maven:org.elasticsearch:*'             = 'elasticsearch'
        'maven:org.liferay.portal:*'            = 'liferay-portal'
        'maven:org.alfresco:*'                  = 'alfresco'

        # --- npm ---------------------------------------------------
        'npm:@angular/core'        = 'angular'
        'npm:@angular/common'      = 'angular'
        'npm:angular'              = 'angularjs'
        'npm:react'                = 'react'
        'npm:react-dom'            = 'react'
        'npm:vue'                  = 'vue'
        'npm:next'                 = 'nextjs'
        'npm:nuxt'                 = 'nuxt'
        'npm:@nestjs/core'         = 'nestjs'
        'npm:svelte'               = 'svelte'
        'npm:electron'             = 'electron'
        'npm:express'              = 'express'
        'npm:jquery'               = 'jquery'
        'npm:bootstrap'            = 'bootstrap'
        'npm:typescript'           = 'typescript'
        'npm:webpack'              = 'webpack'
        'npm:eslint'              = 'eslint'

        # --- PyPI --------------------------------------------------
        'pypi:django'              = 'django'
        'pypi:flask'               = 'flask'
        'pypi:fastapi'             = 'fastapi'
        'pypi:numpy'               = 'numpy'
        'pypi:pandas'              = 'pandas'
        'pypi:celery'              = 'celery'
        'pypi:sqlalchemy'          = 'sqlalchemy'
        'pypi:ansible'             = 'ansible'

        # --- NuGet / .NET ------------------------------------------
        'nuget:Microsoft.AspNetCore.App'        = 'aspnet-core'
        'nuget:Microsoft.NETCore.App'           = 'dotnet'
        'nuget:Microsoft.EntityFrameworkCore'   = 'entity-framework-core'

        # --- PHP / composer ---------------------------------------
        'composer:laravel/framework'            = 'laravel'
        'composer:symfony/symfony'              = 'symfony'
        'composer:symfony/framework-bundle'     = 'symfony'
        'composer:drupal/core'                  = 'drupal'
        'composer:magento/product-community-edition' = 'magento'
    }

    # Prefixes de nom (appliques apres Exact, sur le nom seul, en minuscule)
    Prefix = @{
        'openjdk-'      = 'java'
        'jdk-'          = 'java'
        'python3'       = 'python'
        'nodejs-'       = 'nodejs'
        'postgresql-'   = 'postgresql'
        'tomcat-'       = 'tomcat'
    }
}
