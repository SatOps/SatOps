=begin header
   * Name: satops
   * Description: RHN Satellite API Operator
   * URL: https://github.com/SatOps/SatOps
   * Date: 10 Nov 2013
   * Author: Gilles Dubreuil <gilles@redhat.com>
   * License: Copyright 2011, 2013 Gilles Dubreuil

       This file is part of SatOps.

       SatOps is free software: you can redistribute it and/or modify
       it under the terms of the GNU General Public License as published by
       the Free Software Foundation, either version 3 of the License, or
       (at your option) any later version.

       SatOps is distributed in the hope that it will be useful,
       but WITHOUT ANY WARRANTY; without even the implied warranty of
       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
       GNU General Public License for more details.

       You should have received a copy of the GNU General Public License
       along with SatOps.  If not, see <http://www.gnu.org/licenses/>.
=end

=begin rdoc
Commands provided as parameters at command line are filtered by the Launcher class.
The latter creates a SatOperator object coordinating the operation.

The "Operation" Groups correspond to RHN Satellite objects such as Activation Keys, Software channels, etc.

The SatOperator controls the initial command execution flow for each Operation group.
Every Operation Group builds OperationSet objects, i.e RHN Satellite Set of objects, providing interface to RHN Satellite API to manipulate list of those objects.

At lower level, are RHN Satellite equivalent objects to be copied from or to a Satellite.

Example with RHN Satellite Activation keys.
Activationkey - Class mapping with RHN Satellite objects
   Low level as it interface with RHN API

ActivationkeysSet - Notice plural before the Set
  Subclass of OperationSet
  Wrap/interface/group Activationkey objects

Activationkeys
  Subclass of Operation
  High level view, interfacing commands (export/import/sync,etc) to execute onto the ActivationkeysSet or Activationkey objects.

List of all Operations classes:
Activationkeys, Channels, Configchannels, Kickstarts, KickstartFilepreservations, KickstartKeys, KickstartSnippets, Orgs, OrgTrusts, Systems, SystemCustominfos, Systemgroups, Users
=end

require "logger"
require "xmlrpc/client"
require 'yaml'

def overwrite_net_http
  # https: Client certificate isn't verified by server so each session generates:
  # "warning: peer certificate won't be verified in this SSL session"
  # To get rid of this warning: thanks to http://www.5dollarwhitebox.org/drupal/node/64
  Net::HTTP.class_eval do
    alias_method :old_initialize, :initialize
    def initialize(*args)
      old_initialize(*args)
      @ssl_context = OpenSSL::SSL::SSLContext.new
      @ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
  end
end

require 'satops/helpers'
require 'satops/rhsat'
require 'satops/operator'

def syntax
  %s{
Usage:
  satops show sat | config
  satops -s <sat file> -c <config file> [-dltw] destroy
  satops -s <sat file> -c <config file> [-dltw] export <directory> ascii | bin
  satops -s <sat file> -c <config file> [-dltw] import <directory> ascii | bin
  satops -s <sat file> -c <config file> [-dltw] run <Ruby file>
  satops -s <sat file> -c <config file> [-dltw] extras
  satops -s <sat file> -c <config file> [-dltw] sync
  satops [-h]

Mandatory Configuration:
  Sat file:    Source and Target RHN Satellites definition
  Config file: RHN Satellite objects and options
               Objects must be included to be processed
  Use 'show sat|config' command for generating either templates

Options:
  -d, --debug        Activate debug output
  -l, --log          Append logs to file. By default logs go to Standard Output
  -t, --tls          Activate SSL (HTTPS) sessions
  -w, --warnings     Activate Ruby Verbose

  -h, --help         Display this help and exit

Commands:
  destroy  Delete all objects on target RHN Satellite
  export   Export RHN Satellite objects to files (ascci or binary formats) into <directory>
  extras   Remove objects on target RHN Satellite not present in source RHN Satellite
  import   Import RHN Satellite object from files (ascii or binary) located into  <directory>
  run      Execute Ruby 'plug-in' file
  sync     Synchronise objects from source RHN Satellite to target RHN Satellite
  show     Generate configuration file examples
}
end

def config_syntax
  %s{
# SatOps YAML comprehensive configuration file example
#
# Red Hat Network Satellite object groups
#   Activation Keys, Kickstart Profile, etc, with their specific options
#   An object group must be must be present to have a command executed against it
#
#   Options
#   'update' is a common option to allow corresponding object on target to be updated or not
#   Options are not mandatory - Default values are always either false, '' (empty) or nil
#
# Notes
#   YAML Format
#     Respect indentations using spaces not tabulations
#     Boolean values can be either yes/no or true/false
#     Receivers - left part of assignment are keywords: Do not change them!
#
Activationkeys:
  update: true
Configchannels:
  update: true
  # 'exclude' option provide a way to ignore some Config Channel objects
  # This is a list of regular expressions - Replace
  #exclude:
  #  - !ruby/regexp /^name1$/
  #  - !ruby/regexp /^name2$/
Channels:
  update: true
  delete: false
  # Triggers satellite-sync on Target providing the Source software channels
  iss: false
Kickstarts:
  update: true
KickstartFilepreservations:
  update: true
KickstartKeys:
  update: true
  # Type of keys. Default value is GPG. Other value would be SSL
  key_type: GPG
KickstartSnippets:
  update: true
Orgs:
  update: true
  entitlements: false
OrgTrusts:
  update: true
SystemCustominfos:
  update: true
Systems:
  update: true
Systemgroups:
  update: true
Users:
  update: true
  # Ignore deactivated users
  deactivated: false
  # By default extras users are deactivated not deleted
  delete: false
  # List of accounts to ignore
  exclude:
    - admin
    - satadmin
  # Default password used when creating user on target
  # It cannot be blank
  # When not using password then make sure PAM is activated
  password: "rhnapi"
}
end

def satellites_syntax
%s{
# This is an example of a Satellite configuration file for the satOps
#
# This is a YAML formatted file
# Respect indentations using spaces not tabulations
# Boolean values can be either yes/no or true/false
#
# Do not remove any line
# Change only login and passwd values
--- !ruby/object:Configuration
source: !ruby/object:Host
  name: sat1.example.org
  user:
    :login: admin
    :passwd: redhat
target: !ruby/object:Host
  name: sat2.example.org
  user:
    :login: admin
    :passwd: redhat
  }
end

class Configuration
  attr_reader :source, :target
end

class Host
  attr_reader :name

  def login
    @user[:login]
  end

  def auth
    @user[:passwd]
  end
end

# Satellite Interfacer
class SatOperator
  attr_reader :source, :target, :operations

  # Operations are ordered - It matters for object dependencies
  OPS = [Orgs,
         OrgTrusts,
         Systemgroups,
         Configchannels,
         SystemCustominfos,
         Systems,
         Users,
         Channels,
         Activationkeys,
         KickstartFilepreservations,
         KickstartKeys,
         KickstartSnippets,
         Kickstarts]

  def initialize(options, log)
    @log=log
    @operations=Array.new

    OPS.each do |klass|
      if options.has_key?(klass.to_s)
        # Populate options (class variables) with their values
        klass.class_eval do
          options[klass.to_s].each do |key, val|
            self.instance_variable_set("@#{key}", val)
          end
        end
        # Create Operation objects
        @operations << klass.class_eval { self.new(log) }
      end
    end
  end

  def destroy(target)
    @operations.each do |op|
      op.destroy(target)
    end
  end

  def export(type, sat_source, path)
    @operations.each do |op|
      case type
      when :bin
        op.export(:mrb, sat_source, path)
      when :ascii
        op.export(:yaml, sat_source, path)
      else
        raise "FATAL: No such export format"
      end
    end
  end

  # Extra objects are only present in destination
  # Delete is default operation unless overloaded by OperationSet subclasses.
  def extra(*args)
    @operations.each do |op|
      op.extra(*args)
    end
  end

  def import(type, *args)
    @operations.each do |op|
      case type
      when :bin
        op.import(:mrb, *args)
      when :ascii
        op.import(:yaml, *args)
      else
        raise "FATAL: No such import format"
      end
    end
  end

  def sync(*args)
    @operations.each do |op|
      op.sync(*args)
    end
  end

  def context
    str="\nSatellite Synchronisation Context:\n"
    str << "#{@operations}\n"
  end
end

class Launcher
  def self.usage
    puts syntax
    exit
  end

  def operation_size?(param, size)
    if param.size != size
      Launcher.usage
    end
  end

  def init_source
    RHN::Session.running?(@sat_config.source.name, @ssl)
    @sat_source=RHN::Satellite.new(@sat_config.source, @ssl, @log)
    @sat_source.connect(@sat_config.source)
  end

  def init_target
    RHN::Session.running?(@sat_config.target.name, @ssl)
    @sat_target=RHN::Satellite.new(@sat_config.target, @ssl, @log)
    @sat_target.connect(@sat_config.target)
  end

  def initialize(params)
    @command=""
    @config_file=nil
    @file_to_run=nil
    @options=nil
    @log_file=STDOUT
    @sat_file=nil
    @sat_source=nil
    @sat_target=nil
    @ssl=false

    unless (params.include?('-s') && params.include?('-c')) || params.include?('show')
      Launcher.usage
    end

    until params.empty?
      case params[0]
      when '-c', '--config='
        params.shift
        @config_file=params[0]
      when '-d', '--debug'
        $DEBUG=true
      when '-h', '--help'
        Launcher.usage
      when '-t', '--tls'
        @ssl=true
        overwrite_net_http
      when '-l', '--log='
        params.shift
        @log_file=params[0]
      when '-s', '--satfile='
        params.shift
        @sat_file=params[0]
      when '-w', '--warnings'
        $VERBOSE=true
      when 'clone'
        operation_size?(params, 3)
        @command='clone'
        params.shift
        @name=params[0].to_sym
        params.shift
        @new_name=params[0]
      when 'destroy'
        operation_size?(params, 1)
        @command='destroy'
      when 'sync'
        operation_size?(params, 1)
        @command='sync'
      when 'extras'
        operation_size?(params, 1)
        @command='extra'
      when 'export'
        operation_size?(params, 3)
        @command='export'
        params.shift
        @path=params[0]
        params.shift
        @format=params[0].to_sym
      when 'import'
        operation_size?(params, 3)
        @command='import'
        params.shift
        @path=params[0]
        params.shift
        @format=params[0].to_sym
      when 'run'
        operation_size?(params, 2)
        @command='run'
        params.shift
        @file_to_run=params[0]
      when 'show'
        params.shift
        case params[0]
        when 'sat'
          puts satellites_syntax
        when 'config'
          puts config_syntax
        else
          puts "Use 'show sat' or 'show config' commands"
        end
        exit
      else
        Launcher.usage
      end
      params.shift
    end

    begin
      @log = Logger.new(@log_file)
      @log.datetime_format = "%d/%m/%Y %H:%M:%S"
      if $DEBUG
        @log.level = Logger::DEBUG
      else
        @log.level = Logger::INFO
      end
      @log.info("Starting #{@command.upcase} command")

      # Load satellites details file
      File.open(@sat_file) do |f|
        @sat_config = YAML.load(f)
      end

      # Load operations configuration file
      File.open(@config_file) do |f|
        @options = YAML.load(f)
      end

      case @command
      when 'clone'
        init_target
        SatOperator.new(@options, @log).clone(@name, @new_name)
      when 'destroy'
        init_target
        SatOperator.new(@options, @log).destroy(@sat_target)
      when 'export'
        init_source
        SatOperator.new(@options, @log).export(@format, @sat_source, @path)
      when 'extra'
        init_source
        init_target
        SatOperator.new(@options, @log).extra(@sat_source, @sat_target)
      when 'import'
        init_target
        SatOperator.new(@options, @log).import(@format, @sat_target, @path)
      when 'sync'
        init_source
        init_target
        SatOperator.new(@options, @log).sync(@sat_source, @sat_target)
      when 'run'
        def run
          puts "###\nExcuting #@file_to_run\n###"
          yield
        end
        init_source
        init_target
        lines=""
        File.open(@file_to_run).each do |line|
          lines << line
        end
        block=eval(lines)
        run(&block)
      end
    rescue SystemCallError => e
      @log.fatal "#{e}"
      exit
    ensure
      # Clean-up
      if @sat_source
        @sat_source.terminate
      end
      if @sat_target
        @sat_target.terminate
      end
      @log.info("Finished #{@command.upcase} command")
      @log.close
    end
  end
end
