#!/usr/bin/env ruby

=begin
   * Name: satops
   * Description: RHN Satellite API Operator
   * Author: Gilles Dubreuil <gilles@redhat.com>
   * Date: 22 Jun 2012 
   * Version: 1.3.2
=end

=begin rdoc
Commands provided as parameters at command line are filtered by the Launcher class.
The latter creates a SatOperator object coordinating the operation to execute.

The Operation Groups are matching RHN Satellite objects such as Activation Keys, Software channels, etc.

The SatOperator controls the initial command execution flow for each Operation group.
Every Operation Group builds OperationSet objects, i.e RHN Satellite Set of objects, providing interface to RHN Satellite API to manipulate list of those objects.

At lower level, are RHN Satellite equivalent objects to be copied from or to a Satellite.

Here is an example with RHN Satellite Activation keys.
Activationkey is the Class mapping RHN Satellite objects. Low level
ActivationkeysSet - OperationSet subclass - Notice plural before the Set
                     Manipulate the low level objects Activationkey
Activationkeys - Operation subclass - High level view, wrapping commands (export/import/sync/etc) to execute onto the ActivationkeysSet or Activationkey objects.

Here the exhaustive list of operations classes:
Activationkeys, Channels, Configchannels, Kickstarts, KickstartFilepreservations, KickstartKeys, KickstartSnippets, Systems, SystemCustominfos, Systemgroups, Users
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

module RHN
  # Represent the RHN Satellite XML-RPC server
  module Session
    @@path="/rpc/api" 

    def self.running?(host, ssl)
      server=XMLRPC::Client.new(host, @@path, nil, nil, nil, nil, nil, ssl, 30)
      server.call('api.getVersion')
    rescue Errno::ECONNREFUSED => e
      puts "FATAL: #{sat_host}: #{e}"
      exit
    end

    # Instance methods

    attr_accessor :exception
    
    def connect(sat)
      @server=XMLRPC::Client.new(@host.name, @@path, nil, nil, nil, nil, nil, @ssl, 90)
      @session=@server.call('auth.login', sat.login, sat.auth)
      @exception=nil
    end
    
    def get(command)
      self.exec_async(command)
    end
    
    def run(command, *params)
      @log.debug("API-CALL:#{command} => #{params.inspect}")  
      self.exec_async(command, @session, *params)
    end

    def exec(*params) # command, session 
      begin
        result=@server.call(*params)
        @log.debug("API-RETURN => #{params.inspect}")  
      rescue XMLRPC::FaultException => e
        @exception=e
        @log.debug e.faultCode.to_s+':' + e.faultString
      end
      return result
    end

    # Async call will reconnect if needed
    def exec_async(*params)  # command, session 
      begin 
        result=@server.call_async(*params)
        @log.debug("API-RETURN:#{params.inspect}")  
      rescue XMLRPC::FaultException => e
        @exception=e
        @log.debug e.faultCode.to_s+':' + e.faultString
      end
      return result
    end
    
    def get_exception
      "RHN API Exception:#{@exception.faultCode.to_s}:#{@exception.faultString}" if @exception
    end

    def terminate
      @server.call_async('auth.logout', @session)
    end
  end

  class Operation 
    def initialize(sat)
      @sat=sat
    end
 
    ## Helpers

    # Standard call
    def action(cmd, *args)
      result=@sat.run(cmd, *args) 
      if result
        trace_info(cmd, args[0])
      else 
        trace_warn(cmd, args[0], @sat.get_exception)
      end
      result
    end

    # List call
    def action_list(cmd, *args)
      list=Array.new
      if list=@sat.run(cmd, *args)
        trace_info(cmd, list.size)
      else
        trace_warn(cmd, @sat.get_exception)
      end
      list
    end

    def define(stub, type=nil)
      return if stub.nil?
      stubs=stub.split('.')
      method_name=stubs[stubs.size-1].to_sym
      
      self.class.class_eval do
        case type
        when :list
          define_method(method_name) do |*args|
            action_list(stub, *args)
          end
        when :boolean 
          define_method(method_name) do |*args|
            if action(stub, *args) == 1
              return true
            else
              return false
            end
          end
        else
          define_method(method_name) do |*args|
            action(stub, *args)
          end
        end
      end
    end 
    
    def trace_info(*params)
      str=""
      params.each { |p| str << "#{p}:" } 
      @sat.log.info("#{@sat.host.name}:#{str}")
    end

    def trace_warn(*params)
      str=""
      params.each { |p| str << "#{p}:" } 
      @sat.log.warn("#{@sat.host.name}:#{str}")
    end
  end
  
  class Activationkey < Operation
    def initialize(sat)
      super(sat)
      define 'activationkey.addChildChannels'
      define 'activationkey.addConfigChannels'
      define 'activationkey.addEntitlements'
      define 'activationkey.addPackages'
      define 'activationkey.addServerGroups'
      define 'activationkey.checkConfigDeployment'
      define 'activationkey.delete'
      define 'activationkey.disableConfigDeployment'
      define 'activationkey.enableConfigDeployment'
      define 'activationkey.getDetails'
      define 'activationkey.listActivatedSystems', :list
      define 'activationkey.listActivationKeys', :list
      define 'activationkey.listConfigChannels', :list
      define 'activationkey.removeChildChannels'
      define 'activationkey.removeConfigChannels'
      define 'activationkey.removeEntitlements'
      define 'activationkey.removePackages'
      define 'activationkey.removeServerGroups'
      define 'activationkey.setConfigChannels'
      define 'activationkey.setDetails'
    end

    def create(key, description, base_channel_label, usage_limit, entitlements, universal_default)
      if usage_limit == 0 || usage_limit == nil
        action('activationkey.create', key, description, base_channel_label, entitlements, universal_default)
      else
        action('activationkey.create', key, description, base_channel_label, usage_limit, entitlements, universal_default)
      end
    end

    def exist?(key)
      if get(key)
        return true 
      else
        return false
      end
    end

    def list
      # API doesn't provide a way to distinct from various Reactivation keys.
      keys=[]
      result=self.listActivationKeys
      unless result.nil?
        result.each do |e|
          keys << e unless e['description'] == "Kickstart re-activation key for  ." || e['description'] =~ /^Reactivation key for .*/ || e['description'] =~ /^Activation key for /
        end 
      end
      trace_info('activationkey.listActivationKeys', keys.size)
      keys
    end
  end

  class Channel < Operation
    def initialize(sat)
      super(sat) 
      define 'channel.listAllChannels', :list
      define 'channel.listMyChannels', :list
      define 'channel.listRedHatChannels', :list
    end
  end

  class ChannelSoftware < Operation
    def initialize(sat)
      super(sat) 
      define 'channel.software.create'
      define 'channel.software.delete'
      define 'channel.software.getDetails'
      define 'channel.software.isGloballySubscribable', :boolean
      define 'channel.software.isUserManageable', :boolean
      define 'channel.software.isUserSubscribable', :boolean
      define 'channel.software.setGloballySubscribable'
      define 'channel.software.setUserManageable'
      define 'channel.software.setUserSubscribable'
      define 'channel.software.setDetails'

      # Repos
      define 'channel.software.associateRepo'
      define 'channel.software.createRepo'
      define 'channel.software.disassociateRepo'
      define 'channel.software.getRepoDetails'
      define 'channel.software.getRepoSyncCronExpression'
      define 'channel.software.listChannelRepos'
      define 'channel.software.listUserRepos'
      define 'channel.software.removeRepo'
      define 'channel.software.syncRepo'
      define 'channel.software.updateRepoUrl'
    end
  end

  class Configchannel < Operation
    def initialize(sat)
      super(sat)
      define 'configchannel.channelExists'
      define 'configchannel.create'
      define 'configchannel.deleteChannels'
      define 'configchannel.deleteFiles'
      define 'configchannel.deleteFileRevisions'
      define 'configchannel.getDetails'
      define 'configchannel.getFileRevision'
      define 'configchannel.getFileRevisions'
      define 'configchannel.listFiles', :list
      define 'configchannel.listGlobals', :list
      define 'configchannel.listSubscribedSystems', :list
      define 'configchannel.lookupFileInfo'
      define 'configchannel.update'
    end

    # Class Methods
    # Remove fields not needed for creation from config file 
    def self.copyPath(cf)
      perms=cf["permissions_mode"]
      cf.delete_if { |k,v| k=="modified" || k=="creation" || k=="binary" || k=="channel" || k=="md5" || k=="path" || k=="type" || k == "permissions_mode" || k == "permissions" }
      cf.merge({ "permissions"=> perms.to_s })
    end

    def createOrUpdatePath(label, file, type)
      # Type is boolean : false is file, true is Directory
      path=file['path']
      if type
        file_type='directory'
      else
        file_type='file'
      end
      name="configchannel:createOrUpdatePath"
      result=@sat.run('configchannel.createOrUpdatePath', label, file['path'], type, Configchannel.copyPath(file)) 
      if result
        trace_info(name, label, path)
      else
        case @sat.exception.faultCode
        when 1023
          trace_warn(name, 'Existing', label, path)
        else 
          trace_warn(name, 'KO', label, path, @sat.get_exception)
        end
      end
    end
    
    def createOrUpdateSymlink(label, cfg_file)
      name="configchannel.createOrUpdateSymlink"
      path=cfg_file['path']
      if @sat.run('configchannel.createOrUpdateSymlink', label, cfg_file['path'], {'target_path' => cfg_file['target_path'], 'revision' => cfg_file['revision']})
        trace_info(name, label, path)
      else
        case @sat.exception.faultCode
        when 1023
          trace_warn(name, 'Existing', label, path)
        else 
          trace_warn(name, 'KO', label, path, @sat.get_exception)
        end
      end
    end

    def exist?(cfg_channel)  
      if @sat.run('configchannel.channelExists', cfg_channel['label']) == 1
        return true
      else
        return false
      end
    end
  end

  class Kickstart < Operation
    def initialize(sat)
      super(sat)
      define 'kickstart.createProfile'
      define 'kickstart.deleteProfile'
      define 'kickstart.disableProfile'
      define 'kickstart.isProfileDisabled'
      define 'kickstart.listKickstarts', :list
    end
  end

  class KickstartFilepreservation < Operation
    def initialize(sat)
      super(sat)
      define 'kickstart.filepreservation.create'
      define 'kickstart.filepreservation.delete'
      define 'kickstart.filepreservation.getDetails'
      define 'kickstart.filepreservation.listAllFilePreservations', :list
    end

    def exist?(name)
      if get(name)
        return true
      else
        return false
      end
    end

    def get(name)
      action('kickstart.filepreservation.getDetails', name)
    rescue RuntimeError # Workaround for bug 'cause empty
      return nil
    end
  end

  class KickstartKeys < Operation
    def initialize(sat)
      super(sat)
      define 'kickstart.keys.create'
      define 'kickstart.keys.delete'
      define 'kickstart.keys.getDetails'
      define 'kickstart.keys.listAllKeys', :list
      define 'kickstart.keys.update'
    end
  end

  class KickstartProfile < Operation
    def initialize(sat)
      super(sat)
      define 'kickstart.profile.addIpRange'
      define 'kickstart.profile.addScript'
      define 'kickstart.profile.getAdvancedOptions'
      define 'kickstart.profile.getChildChannels'
      define 'kickstart.profile.getCustomOptions'
      define 'kickstart.profile.getKickstartTree'
      define 'kickstart.profile.getVariables'
      define 'kickstart.profile.listScripts'
      define 'kickstart.profile.listIpRanges', :list
      define 'kickstart.profile.removeScript'
      define 'kickstart.profile.setAdvancedOptions'
      define 'kickstart.profile.setChildChannels'
      define 'kickstart.profile.setCustomOptions'
      define 'kickstart.profile.setKickstartTree'
      define 'kickstart.profile.setLogging'
      define 'kickstart.profile.setVariables'
    end
  end

  class KickstartProfileSoftware < Operation
    def initialize(sat)
      super(sat)
      define 'kickstart.profile.software.getSoftwareList', :list
      define 'kickstart.profile.software.setSoftwareList'
    end
  end

  class KickstartProfileSystem < Operation
    def initialize(sat)
      super(sat)
      define 'kickstart.profile.system.addFilePreservations'
      define 'kickstart.profile.system.addKeys'
      define 'kickstart.profile.system.checkConfigManagement'
      define 'kickstart.profile.system.checkRemoteCommands'
      define 'kickstart.profile.system.disableConfigManagement'
      define 'kickstart.profile.system.disableRemoteCommands'
      define 'kickstart.profile.system.enableConfigManagement'
      define 'kickstart.profile.system.enableRemoteCommands'
      define 'kickstart.profile.system.getLocale'
      define 'kickstart.profile.system.getPartitioningScheme'
      define 'kickstart.profile.system.getRegistrationType'
      define 'kickstart.profile.system.getSELinux'
      define 'kickstart.profile.system.listFilePreservations', :list
      define 'kickstart.profile.system.listKeys', :list
      define 'kickstart.profile.system.setLocale'
      define 'kickstart.profile.system.setPartitioningScheme'
      define 'kickstart.profile.system.setRegistrationType'
      define 'kickstart.profile.system.setSELinux'
    end
  end

  class KickstartSnippet < Operation
    def initialize(sat)
      super(sat)
      define 'kickstart.snippet.createOrUpdate' 
      define 'kickstart.snippet.delete' 
      define 'kickstart.snippet.listCustom', :list 
    end
  end

  class System < Operation   
    def initialize(sat)
      super(sat)
      define 'system.listSystems'
      define 'system.deleteSystems'
      define 'system.getDetails'
      define 'system.getConnectionPath'
      define 'system.getCpu'
      define 'system.getCustomValues'
      define 'system.getDevices'
      define 'system.getDmi'
      define 'system.getEntitlements'
      define 'system.getEventHistory'
      define 'system.getMemory'
      define 'system.getName'
      define 'system.getNetwork'
      define 'system.getNetworkDevices'
      define 'system.getRegistrationDate'
      define 'system.getRunningKernel'
      define 'system.getSubscribedBaseChannel'
    end
  end

  class SystemConfig < Operation   
    def initialize(sat)
      super(sat)
      define 'system.config.addChannels'
      define 'system.config.listChannels'
      define 'system.config.removeChannels'
    end
  end

  class SystemCustominfo < Operation 
    def initialize(sat)
      super(sat)
      define 'system.custominfo.createKey'
      define 'system.custominfo.deleteKey'
      define 'system.custominfo.listAllKeys', :list
      define 'system.custominfo.updateKey'
    end
  end

  class Systemgroup < Operation 
    def initialize(sat)
      super(sat)
      define 'systemgroup.create'
      define 'systemgroup.delete'
      define 'systemgroup.getDetails' # Accepts System Group name or id
      define 'systemgroup.listAllGroups', :list
      define 'systemgroup.update'
    end

    def exist?(name)  
      if self.getDetails(name)
        true
      else
        false
      end
    end
  end

  class User < Operation
    def initialize(sat)
      super(sat)
      define 'user.addAssignedSystemGroups'
      define 'user.addDefaultSystemGroups'
      define 'user.addRole'
      define 'user.create'
      define 'user.delete'
      define 'user.disable'
      define 'user.enable'
      define 'user.getDetails'
      define 'user.listAssignedSystemGroups', :list
      define 'user.listDefaultSystemGroups', :list
      define 'user.listRoles', :list
      define 'user.listUsers', :list
      define 'user.removeRole'
      define 'user.setDetails'
    end
    
    def to_s
    str=""
      super('user.listUsers').each do |user| 
        str << "User #{user['login']}\n"
        str << "Roles"
        action('user.listRoles', user['login']).each do |role| 
          str << ":#{role}"
        end
        str << "\nAssigned System Groups"
        action('user.listAssignedSystemGroups', user['login']).each do |group| 
          str << ":#{group['name']}"
        end
          str << "\nDefault System Groups"
        action('user.listDefaultSystemGroups', user['login']).each do |def_group| 
          str << ":#{def_group['name']}"
        end
        str << "\n"
      end
      str
    end
  end

  # Interface to Red Hat Network Satellite API
  # Can be invoked with satellite object : sat.channel.create()
  class Satellite
    include Session
    attr_reader :host, :log, :activationkey, :channel, :channelSoftware, :configchannel, :kickstart, :kickstartFilepreservation, :kickstartProfile, :kickstartProfileSystem, :kickstartProfileSoftware, :kickstartKeys, :kickstartSnippet, :system, :systemConfig, :systemCustominfo, :systemgroup, :user

    def initialize(sat_host, ssl, log)
      @host=sat_host
      @ssl=ssl
      @log=log
      @session=nil
      @activationkey=Activationkey.new(self)
      @channel=Channel.new(self)
      @channelSoftware=ChannelSoftware.new(self)
      @configchannel=Configchannel.new(self)
      @kickstart=Kickstart.new(self)
      @kickstartFilepreservation=KickstartFilepreservation.new(self)
      @kickstartProfile=KickstartProfile.new(self)
      @kickstartProfileSystem=KickstartProfileSystem.new(self)
      @kickstartProfileSoftware=KickstartProfileSoftware.new(self)
      @kickstartKeys=KickstartKeys.new(self)
      @kickstartSnippet=KickstartSnippet.new(self)
      @system=System.new(self)
      @systemConfig=SystemConfig.new(self)
      @systemCustominfo=SystemCustominfo.new(self)
      @systemgroup=Systemgroup.new(self)
      @user=User.new(self)
    end
  end
end

module Helpers  
  def self.filter(hash, filter)
    list=[]
    unless hash.nil?
      hash.each do |e| 
        list << e[filter]
      end
    end
    list
  end
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

class OperationSet
  attr_reader :list

  def initialize(sat)
    @sat=sat
    @list=[]
  end

  def extra(list)
    delete(list)
  end

  def fetch
    @list=fetch_all
  end
  
  # Create include methods
  %w{description id key label login name}.each do |method|
    define_method("include_#{method}?".to_sym) do |o|
      result=false
      @list.each do |e|
        result=true if eval("e.#{method} == o.#{method}")
      end
      result
    end
  end

  def -(val)
    result=[]
    @list.each do |e|
      result << e unless val.include?(e)
    end
    result
  end
end

class Operation
  class << self
    attr_accessor :update
  end
  @update=false

  attr_reader :log

  def initialize(log)
    # Family is associated operation's group class: i.e 'UsersSet' for 'Users'
    @family=Kernel.const_get(self.class.to_s+'Set')
    @log=log
    @log.info "Init #{self.class.to_s}"
  end

  def create(sat)
    @family.class_eval { return self.new(sat) }
  end

  def clone(sat, src_name, dst_name)
    @log.info "Cloning #{self.class}"
  end

  def destroy(sat) 
    @log.info "Deleting #{self.class}" 
    satobjects=create(sat)
    satobjects.delete_all
  end

  def export(type, sat, path)
    @log.info "Exporting #{self.class}"
    
    satobjects=create(sat)
    satobjects.fetch
    case type
    when :mrb 
      File.open("#{path}/#{self.class}.mrb", "w+") do |f|
        Marshal.dump(satobjects.list, f)
      end
    when :yaml 
      File.open("#{path}/#{self.class}.yaml", "w+") do |f|
        YAML.dump(satobjects.list, f)
      end
    end
  end

  def import(type, sat, path) 
    @log.info "Importing #{self.class}"
    satobjects=[] 
    case type
    when :mrb
      File.open("#{path}/#{self.class}") do |f|
        satobjects = Marshal.load(f)
      end
    when :yaml
      File.open("#{path}/#{self.class}.yaml") do |f|
        satobjects = YAML.load(f)
      end
    end
    dst_satobjects=create(sat)
    dst_satobjects.fetch
    unless satobjects.nil?
      satobjects.each do |satobject|
        if self.class.update && dst_satobjects.include?(satobject)
          satobject.update(sat)
        else 
          satobject.create(sat)
        end
      end
    end
  end

  def presync(src_sat, dst_sat)
  end

  def postsync(src_sat, dst_sat)
  end

  def extra(src_sat, dst_sat)
    @log.info "Applying extra #{self.class}"
    src_satobjects=create(src_sat)
    src_satobjects.fetch
    dst_satobjects=create(dst_sat)
    dst_satobjects.fetch

    satobjects_extras=[]
    satobjects_extras=dst_satobjects-src_satobjects
    dst_satobjects.extra(satobjects_extras) unless satobjects_extras.empty?
  end

  def sync(src_sat, dst_sat)
    @log.info  "Synchronizing #{self.class}"
    src_satobjects=create(src_sat)
    src_satobjects.fetch
    dst_satobjects=create(dst_sat)
    dst_satobjects.fetch
    presync(src_sat, dst_sat)
    unless src_satobjects.nil?
      src_satobjects.list.each do |src_satobject|
        if self.class.update && dst_satobjects.include?(src_satobject)
          src_satobject.update(dst_sat)
        else
          src_satobject.create(dst_sat)
        end
      end
    end
    postsync(src_sat, dst_sat)
  end
end

class Activationkeys < Operation
end

class Channels < Operation
  class << self
    attr_accessor :delete, :iss
  end
  @delete=false
  @iss=false

  def presync(src_sat, dst_sat)
    if Channels.iss
      all_channels=Helpers.filter(src_sat.channel.listAllChannels, 'label').sort
      @result=nil
      3.times do
        iss_cmd="/usr/bin/ssh -q root@#{dst_sat.host.name} '/usr/bin/satellite-sync "
        all_channels.each do |e|
          iss_cmd << "-c #{e} " 
        end  
        iss_cmd << "; echo $?'"
        @log.info iss_cmd
        @result=%x(#{iss_cmd})
        @log.info @result 
        break if @result.chomp.reverse[0,1] == '0'
      end
      raise "Fatal: ISS Failed" if @result.chomp.reverse[0,1] != '0'
    end
  rescue RuntimeError => e
    @log.fatal "#{e}" 
  end
end

class Configchannels < Operation
  class << self
    attr_accessor :exclude
  end
  @exclude=[]
end

class Kickstarts < Operation
end

class KickstartFilepreservations < Operation
end

class KickstartKeys < Operation
  class << self
    attr_accessor :key_type
  end
  @key_type='GPG'
end

class KickstartSnippets < Operation
end

class Systems < Operation
end

class SystemCustominfos < Operation
end

class Systemgroups < Operation
end

class Users < Operation
  class << self
    attr_accessor :delete, :deactivated, :exclude, :password
  end
  @delete=false
  @deactivated=false
  @exclude=[]
  @password=''
end

class Activationkey
  attr_reader :key, :child_channel_labels, :config_channel_labels, :packages, :entitlements, :server_group_ids

  def self.reader(sat, key)
    activation_key=sat.activationkey.getDetails(key)
    activation_key.merge!('config_channel_labels'=>Helpers.filter(sat.activationkey.listConfigChannels(activation_key['key']), 'label'))
    activation_key.merge!('server_group_names'=>ActivationkeysSet.get_server_groups_names(sat, activation_key['server_group_ids']))
    activation_key.merge!('config_deployment'=>sat.activationkey.checkConfigDeployment(key))
    activation_key
  end

  def self.remove_id(key)
    str=""
    if key =~ /^[0-9]*-/
      # key starts with an org id so we remove it as it's added by Satellite
      str=key.sub(/^[0-9]*-/, '') 
    else
      str=key
    end
  end

  def initialize(activation_key)
    @key=activation_key['key']
    @description=activation_key['description']
    @base_channel_label=activation_key['base_channel_label']
    @child_channel_labels=activation_key['child_channel_labels']
    @config_channel_labels=activation_key['config_channel_labels']
    @config_deployment=activation_key['config_deployment']
    @entitlements=activation_key['entitlements']
    @packages=activation_key['packages']
    @server_group_ids=activation_key['server_group_ids']
    @server_group_names=activation_key['server_group_names']
    @universal_default=activation_key['universal_default']
    @usage_limit=activation_key['usage_limit']
    @disabled=activation_key['disabled']
  end

  def common_update(sat)
    sat.activationkey.addEntitlements(@key, @entitlements)   
    sat.activationkey.enableConfigDeployment(@key) if @config_deployment
    sat.activationkey.addChildChannels(@key, @child_channel_labels)
    sat.activationkey.addConfigChannels([@key], @config_channel_labels, true)
    sat.activationkey.addPackages(@key, @packages) 
    sat.activationkey.addServerGroups(@key, ActivationkeysSet.get_server_groups_ids(sat, @server_group_names))
  end

  def create(sat)
    common_update(sat) if sat.activationkey.create(Activationkey.remove_id(@key), @description,  @base_channel_label, @usage_limit, @entitlements, @universal_default)
  end
   
  def update(sat)
    # Sync base channel field
    orig=Activationkey.new(Activationkey.reader(sat, @key))
    @base_channel_label='' if @base_channel_label== 'none'
    @usage_limit=-1 if @usage_limit == 0
    sat.activationkey.setDetails(@key, {'description' => @description, 'base_channel_label' => @base_channel_label, 'usage_limit' => @usage_limit, 'universal_default' => @universal_default, 'disabled' => @disabled})
    sat.activationkey.removeChildChannels(@key, orig.child_channel_labels)
    sat.activationkey.removeConfigChannels([@key], orig.config_channel_labels)
    sat.activationkey.removePackages(@key, orig.packages) # must be done before removing entitlements!  
    sat.activationkey.removeServerGroups(@key, orig.server_group_ids)
    sat.activationkey.disableConfigDeployment(@key)
    sat.activationkey.removeEntitlements(@key, orig.entitlements) 
    common_update(sat)
  end
end

class ActivationkeysSet < OperationSet
  # Grab server group ids using names
  def self.get_server_groups_ids(sat, names)
    server_group_ids=[]
    names.each do |e|
      server_group_ids << sat.systemgroup.getDetails(e)['id']
    end
    server_group_ids
  end

  # Grab server group names using ids
  def self.get_server_groups_names(sat, ids)
    server_group_names=Array.new
    ids.each do |e|
      server_group=sat.systemgroup.getDetails(e)
      server_group_names << server_group['name']
    end
    server_group_names
  end

  def delete(list)
    list.each do |activation_key|
      if activation_key.class == Activationkey
        @sat.activationkey.delete(activation_key.key) 
      else
        @sat.activationkey.delete(activation_key['key']) 
      end
    end
  end

  def delete_all
    delete(@sat.activationkey.list)
  end

  def fetch_all
    activation_keys=[]
    @sat.activationkey.list.each do |activation_key|
     activation_keys << Activationkey.new(Activationkey.reader(@sat, activation_key['key']))
    end   
    activation_keys
  end

  def include?(arg)
    self.include_key?(arg)
  end
end

class Channel
  attr_reader :id, :label
  REDHAT="Red Hat, Inc." 

  def self.reader(sat, channel)
    channel.merge!(sat.channelSoftware.getDetails(channel['label']))
    channel.merge!({'isGloballySubscribable'=>sat.channelSoftware.isGloballySubscribable(channel['label'])})
    unless channel['isGloballySubscribable']
      subscribers={}
      Helpers.filter(sat.user.listUsers, 'login').each do |login|
        subscribers.merge!({login => sat.channelSoftware.isUserSubscribable(channel['label'], login)})
      end
      channel.merge!({'subscribers'=>subscribers})
    end
    unless channel['provider_name'] == REDHAT 
      managers={}
      Helpers.filter(sat.user.listUsers, 'login').each do |login|
        managers.merge!({login =>  sat.channelSoftware.isUserManageable(channel['label'], login)})
      end
      channel.merge!({'managers'=>managers})
    end
    channel
  end

  def initialize(channel)
    @id=channel['id'] 
    @label=channel['label'] 
    @name=channel['name'] 
    @arch_name=channel['arch_name'] 
    @summary=channel['summary']
    @provider_name= channel['provider_name'] 
    @packages=channel['packages'] 
    @systems=channel['systems']
    @is_globally_subscribable=channel['isGloballySubscribable']
    @subscribers=channel['subscribers']
    @managers=channel['managers']
    @description=channel['description'] 
    @checksum_label=channel['checksum_label']
    @last_modified=channel['last_modified'] 
    @maintainer_name=channel['maintainer_name'] 
    @maintainer_email=channel['maintainer_email']
    @maintainer_phone=channel['maintainer_phone'] 
    @support_policy=channel['support_policy'] 
    @gpg_key_url=channel['gpg_key_url'] 
    @gpg_key_id=channel['gpg_key_id'] 
    @gpg_key_fp=channel['gpg_key_fp'] 
    @yumrepo_source_url=channel['yumrepo_source_url'] 
    @yumrepo_label=channel['yumrepo_label'] 
    @yumrepo_last_sync=channel['yumrepo_last_sync'] 
    @end_of_life=channel['end_of_life']
    @parent_channel_label=channel['parent_channel_label']
    @clone_original=channel['clone_original']
  end

  def create(sat)
    # Software Channels must created via ISS (satellite-sync)
  end

  def update(sat) 
    # Update details for non Red Hat channels
    if @provider_name != REDHAT
      # Non mandatory fields that could be nil need to be empty 
      @maintainer_name='' unless @maintainer_name
      @maintainer_email='' unless @maintainer_email
      @maintainer_phone='' unless @maintainer_phone
      # Find target channel id
      id=sat.channelSoftware.getDetails(@label)['id'] 
      sat.channelSoftware.setDetails(id, {'checksum_label' => @checksum_label, 'name' => @name, 'summary' => @summary, 'description' => @description, 'maintainer_name' => @maintainer_name, 'maintainer_email' => @maintainer_email, 'maintainer_phone' => @maintainer_phone, 'gpg_key_url' => @gpg_key_url, 'gpg_key_id' => @gpg_key_id, 'gpg_key_fp' => @gpg_key_fp})

      # Managers 
      if @managers
        @managers.each do |login, value|
          sat.channelSoftware.setUserManageable(@label, login, value)
        end
      end
    end 

    # Globally Subscribable
    sat.channelSoftware.setGloballySubscribable(@label, @is_globally_subscribable)
    
    # Per User subscriptions
    if !@is_globally_subscribable && @subscribers
      @subscribers.each do |login, value|
        sat.channelSoftware.setUserSubscribable(@label, login, value)
      end
    end

    # To Do : Repos
  end
end

class ChannelsSet < OperationSet
  def delete(list)
    list.each do |channel| 
      # To Fix - Stuct vs object issue
      if channel.class == Channel
        @sat.channelSoftware.delete(channel.label)
      else 
        @sat.channelSoftware.delete(channel['label'])
      end
    end
  end

  def delete_all
    # Flag must be set!
    delete(@sat.channel.listMyChannels) if Channels.delete
  end

  def fetch_all 
    channels=[]
    @sat.channel.listAllChannels.each do |channel|
      channels << Channel.new(Channel.reader(@sat, channel))
    end
    channels
  end

  def include?(arg)
    self.include_label?(arg)
  end
end

class Configchannel
  attr_reader :label
  
  def self.reader(sat, id)
    # Configchannel files are files, directories or symlinks
    configchannel ={}
    configchannel.merge!(sat.configchannel.getDetails(id))
  
    file_revisions=Hash.new
    sat.configchannel.listFiles(configchannel['label']).each do |file|
      file_revisions.merge!("#{file['path']}" => sat.configchannel.getFileRevisions(configchannel['label'], file['path']))
    end
    configchannel.merge!({'file_revisions' => file_revisions})
    configchannel
  end

  def initialize(configchannel)
    @id=configchannel['id']
    @orgId=configchannel['orgId']
    @label=configchannel['label']
    @name=configchannel['name']
    @description=configchannel['description']
    @configChannelType=configchannel['configChannelType']
    @file_revisions=configchannel['file_revisions']
  end

  def set_files(sat, cfg_file)
    case cfg_file['type']
    when 'file'
      sat.configchannel.createOrUpdatePath(@label, cfg_file, false)
    when 'directory'
      sat.configchannel.createOrUpdatePath(@label, cfg_file, true)
    when 'symlink'
      sat.configchannel.createOrUpdateSymlink(@label, cfg_file)
    end
  end

  def create(sat)
    sat.configchannel.create(@label, @name, @description)
    # Create file revisions
    @file_revisions.each do |cfg_file, revisions|
      revisions.each do |file_revision| 
        set_files(sat, file_revision)
      end
    end
  end  

  def update(sat)
    sat.configchannel.update(@label, @name, @description)

    @file_revisions.each do |cfg_file, revisions| 
    #  dst_cfg_files=sat.configchannel.deleteFiles(@label, [cfg_file])
      revisions.each do |file_revision| 
        set_files(sat, file_revision)
      end
    end
  end 
end

class ConfigchannelsSet < OperationSet
  def delete(array_list)
    list=Array.new
    array_list.each do |configchannel|
      # To Fix - When using delete_all from destroy we are handling struct not Channelconfig object!
      if configchannel.class == Configchannel
        list << configchannel.label 
      else
        list << configchannel['label']
      end
    end
    @sat.configchannel.deleteChannels(list)
  end

  def delete_extra_files
    if @delete_extra
      target_files=Helpers.filter(target.configchannel.listFiles(cfg_channel['label']), 'path')
      delete_file_list=target_files - source_files
      target.configchannel.deleteFiles(cfg_channel['label'], delete_file_list) unless delete_file_list.empty?
    end
  end

  def delete_all
    self.delete(@sat.configchannel.listGlobals)
  end
  
  def fetch_all
    configchannels=[]
    @sat.configchannel.listGlobals.each do |config_channel|
      configchannels << Configchannel.new(Configchannel.reader(@sat, config_channel['id']))
    end

    # Apply exclude list option 
    if Configchannels.exclude
       Configchannels.exclude.each do |exclude|
        case exclude
        when Regexp
          configchannels.delete_if { |u| u.label =~ exclude }
        when String
          configchannels.delete_if { |u| u.label == exclude }
        end
      end
    end
    configchannels
  end

  def include?(arg)
    self.include_label?(arg)
  end
end

class Kickstart
  attr_reader :label

  def self.reader(sat, ks)
    label=ks['label']
    kickstart=ks
    kickstart.merge!({'advanced_options'=>sat.kickstartProfile.getAdvancedOptions(label)})
    kickstart.merge!({'child_channels'=>sat.kickstartProfile.getChildChannels(label)})
    kickstart.merge!({'custom_options'=>sat.kickstartProfile.getCustomOptions(label)})
    kickstart.merge!({'variables'=>sat.kickstartProfile.getVariables(label)})   
    
    kickstart.merge!({'config_management'=>sat.kickstartProfileSystem.checkConfigManagement(label)})  
    kickstart.merge!({'remote_commands'=>sat.kickstartProfileSystem.checkRemoteCommands(label)})
    kickstart.merge!({'locale'=>sat.kickstartProfileSystem.getLocale(label)})
    kickstart.merge!({'selinux'=>sat.kickstartProfileSystem.getSELinux(label)})
    kickstart.merge!({'partitioning_scheme'=>sat.kickstartProfileSystem.getPartitioningScheme(label)})
    kickstart.merge!({'registration_type'=>sat.kickstartProfileSystem.getRegistrationType(label)})
    kickstart.merge!({'software_list'=>sat.kickstartProfileSoftware.getSoftwareList(label)})
    
    kickstart.merge!({'keys'=>Helpers.filter(sat.kickstartProfileSystem.listKeys(label), 'description')})
    kickstart.merge!({'file_preservations'=>Helpers.filter(sat.kickstartProfileSystem.listFilePreservations(label), 'name')})
    kickstart.merge!({'scripts'=>sat.kickstartProfile.listScripts(label)})
    kickstart
  end
  
  def initialize(kickstart)
    @label=kickstart['label']
    @tree_label=kickstart['tree_label']
    @name=kickstart['name']
    @advanced_mode=kickstart['advanced_mode']
    @org_default=kickstart['org_default']
    @active=kickstart['active']
    @advanced_options=kickstart['advanced_options']
    @child_channels=kickstart['child_channels']
    @custom_options=kickstart['custom_options']
    @variables=kickstart['variables']
    @config_management=kickstart['config_management']
    @remote_commands=kickstart['remote_commands']
    @locale=kickstart['locale']
    @selinux=kickstart['selinux']
    @partitioning_scheme=kickstart['partitioning_scheme']
    @registration_type=kickstart['registration_type']
    @software_list=kickstart['software_list'] 
    @keys=kickstart['keys']
    @file_preservations=kickstart['file_preservations']
    @scripts=kickstart['scripts']
  end

  def create(sat)
    sat.kickstart.createProfile(@label, 'none', @tree_label, 'default', '')
    sat.kickstart.disableProfile(@label, !@active)

    sat.kickstartProfile.setAdvancedOptions(@label, @advanced_options)
    sat.kickstartProfile.setCustomOptions(@label, @custom_options) 
    sat.kickstartProfile.setVariables(@label, @variables) 
    sat.kickstartProfile.setChildChannels(@label, @child_channels)
    sat.kickstartProfile.setKickstartTree(@label, @tree_label)
    sat.kickstartProfile.setLogging(@label, true, true)  # No API for logging option - Activate them by default

    sat.kickstartProfileSystem.setLocale(@label, @locale['locale'], @locale['useUtc'])
    sat.kickstartProfileSystem.setSELinux(@label, @selinux) 
    sat.kickstartProfileSystem.setPartitioningScheme(@label, @partitioning_scheme)
    sat.kickstartProfileSystem.setRegistrationType(@label, @registration_type)
    sat.kickstartProfileSystem.addKeys(@label, @keys)
    sat.kickstartProfileSystem.addFilePreservations(@label, @file_preservations) 
    sat.kickstartProfileSoftware.setSoftwareList(@label, @software_list)

    if @config_management
      sat.kickstartProfileSystem.enableConfigManagement(@label)
    else
      sat.kickstartProfileSystem.disableConfigManagement(@label)
    end
 
    if @remote_commands
      sat.kickstartProfileSystem.enableRemoteCommands(@label)
    else
      sat.kickstartProfileSystem.disableRemoteCommands(@label)
    end

    @scripts.each do |script|
      sat.kickstartProfile.addScript(@label, script['contents'], script['interpreter'], script['script_type'], script['chroot'], script['template'])
    end
  end

  def update(sat)
    # Remove scripts first because there is no RHN API call for updating them 
    Helpers.filter(sat.kickstartProfile.listScripts(@label), 'id').each do |id|
      sat.kickstartProfile.removeScript(@label, id)
    end
    # No API for updating KS profile so we overide
    self.create(sat)
  end
end

class KickstartsSet < OperationSet
  def delete(list)
    list.each do |ks|
      if ks.class == Kickstart
        @sat.kickstart.deleteProfile(ks.label)
      else
        @sat.kickstart.deleteProfile(ks['label']) 
      end
    end
  end

  def delete_all
    delete(@sat.kickstart.listKickstarts)
  end

  def fetch_all
    kickstarts=[]
    @sat.kickstart.listKickstarts.each do |ks|
      kickstarts << Kickstart.new(Kickstart.reader(@sat, ks))
    end
    kickstarts
  end

  def include?(arg)
    self.include_label?(arg)
  end
end

class KickstartFilepreservation
  attr_reader :name

  def self.reader(sat, file_preserv)
    file_preserv.merge!({'file_list'=>sat.kickstartFilepreservation.get(file_preserv['name'])['file_names']})
    file_preserv
  end
  
  def initialize(file_preserv)
    @id=file_preserv['id']
    @name=file_preserv['name']
    @file_list=file_preserv['file_list']
  end

  def delete(sat)
    sat.kickstartFilepreservation.delete(@name)
  end

  def create(sat)
    sat.kickstartFilepreservation.create(@name, @file_list)
  end

  def update(sat)
    # No API for update 
    self.delete(sat)
    self.create(sat)
  end
end

class KickstartFilepreservationsSet < OperationSet
  def delete(list)
    list.each do |file_preserv|
      if file_preserv.class == KickstartFilepreservation
        @sat.kickstartFilepreservation.delete(file_preserv.name)
      else
        @sat.kickstartFilepreservation.delete(file_preserv['name']) 
      end
    end
  end

  def delete_all
    delete(@sat.kickstartFilepreservation.listAllFilePreservations)
  end

  def fetch_all
    file_perservations=[]
    @sat.kickstartFilepreservation.listAllFilePreservations.each do |file_preserv|
      file_perservations << KickstartFilepreservation.new(KickstartFilepreservation.reader(@sat, file_preserv))
    end 
   file_perservations
  end

  def include?(arg)
    self.include_name?(arg)
  end
end

# GPG/SSL Keys
class KickstartKey
  attr_reader :description

  def initialize(key)
    @description=key['description']
    @type=key['type']
    @content=key['content']
  end

  def delete(sat)
    sat.kickstartKeys.delete(@description)
  end

  def create(sat)
    sat.kickstartKeys.create(@description, @type, @content)
  end
  
  def update(sat)
    sat.kickstartKeys.update(@description, @type, @content)
  end
end

class KickstartKeysSet < OperationSet
  def delete(list)
    list.each do |ks_key|
      if ks_key.class == KickstartKey
        @sat.kickstartKeys.delete(ks_key.description) 
      else
        @sat.kickstartKeys.delete(ks_key['description']) 
      end
    end
  end

  def delete_all
    delete(get_all)
  end

  def fetch_all
    ks_keys=[]
    get_all.each do |ks|
      ks_keys << KickstartKey.new(ks)
    end
    ks_keys
  end

  def get_all
    # Fetch only kickstart keys matching key_type option
    key_type=KickstartKeys.key_type
    return [] unless key_type
    ksdetails=[]
    @sat.kickstartKeys.listAllKeys.each do |ks_key| 
      ksdetails.push(@sat.kickstartKeys.getDetails(ks_key['description'])) if ks_key['type'] == key_type
    end
    ksdetails
  end 

  def include?(arg)
    self.include_description?(arg)
  end
end

class KickstartSnippet
  attr_reader :name
  
  def initialize(snippet)
    @name=snippet['name']
    @contents=snippet['contents']
  end

  def delete(sat)
    sat.kickstartSnippet.delete(@name)
  end

  def create(sat)
    sat.kickstartSnippet.createOrUpdate(@name, @contents)
  end

  def update(sat)
    self.create(sat)
  end
end

class KickstartSnippetsSet < OperationSet
  def delete(list)
    list.each do |snippet|
      if snippet.class == KickstartSnippet
        @sat.kickstartSnippet.delete(snippet.name)
      else
        @sat.kickstartSnippet.delete(snippet['name'])
      end
    end
  end

  def delete_all
    delete(@sat.kickstartSnippet.listCustom)
  end

  def fetch_all
    snippets=[]
    @sat.kickstartSnippet.listCustom.each do |snippet|
      snippets << KickstartSnippet.new(snippet)
    end
    snippets
  end

  def include?(arg)
    self.include_name?(arg)
  end
end

class System 
  attr_reader :id

  def self.reader(sat, id)
    system={}
    system.merge!(sat.system.getDetails(id))
    system.merge!({'connection_path'=>sat.system.getConnectionPath(id)})
    system.merge!({'cpu'=>sat.system.getCpu(id)})
    system.merge!({'custom_values'=>sat.system.getCustomValues(id)})
    system.merge!({'devices'=>sat.system.getDevices(id)})
    system.merge!({'dmi'=>sat.system.getDmi(id)})
    system.merge!({'entitlements'=>sat.system.getEntitlements(id)})
    system.merge!({'event_history'=>sat.system.getEventHistory(id)})
    system.merge!({'memory'=>sat.system.getMemory(id)})
    system.merge!({'name'=>sat.system.getName(id)})
    system.merge!({'network'=>sat.system.getNetwork(id)})
    system.merge!({'network_devices'=>sat.system.getNetworkDevices(id)})
    system.merge!({'registration_date'=>sat.system.getRegistrationDate(id)})
    system.merge!({'running_kernel'=>sat.system.getRunningKernel(id)})
    system.merge!({'subscribed_base_channel'=>sat.system.getSubscribedBaseChannel(id)})
    system
  end

  def initialize(system)
    @id=system['id']
    @profile_name=system['profile_name']
    @base_entitlement=system['base_entitlement']
    @addon_entitlement=system['']
    @auto_update=system['auto_update']
    @release=system['release']
    @address1=system['address1']
    @address2=system['address2']
    @city=system['city']
    @state=system['state']
    @country=system['country']
    @building=system['building']
    @room=system['room']
    @rack=system['rack']
    @description=system['description']
    @hostname=system['hostname']
    @last_boot=system['last_boot']
    @osa_satus=system['osa_status']
    @lock_status=system['lock_status']
    @connection_path=system['connection_path']
    @cpu=system['cpu']
    @custom_values=system['custom_values=']
    @devices=system['devices']
    @dmi=system['dmi']
    @entitlements=system['entitlements']
    @event_history=system['event_history']
    @memory=system['memory']
    @name=system['name']
    @network=system['network']
    @network_devices=system['network_devices']
    @registration_date=system['registration_date']
    @running_kernel=system['running_kernel']
    @subscribed_base_channel=system['subscribed_base_channel']
  end

  # System profiles must be registered and cannot be created
  def create(sat)
  end

  def update(sat)
  end
end

class SystemsSet < OperationSet
  def delete(list)
    # To Test
    list=[list] if list.class != Array
    @sat.system.deleteSystems(Helpers.filter(list, 'id')) 
  end

  def delete_all
    delete(@sat.system.listSystems)
  end

  def fetch_all
    systems=[]
    @sat.system.listSystems.each do |sys|
      systems << System.new(System.reader(@sat, sys['id']))
    end
    systems
  end

  def include?(arg)
    self.include_id?(arg)
  end
end

class SystemCustominfo 
  attr_reader :id, :label

  def initialize(system)
    @id=system['id']
    @label=system['label']
    @description=system['description']
    @last_modified=system['last_modified']
    @system_count=system['system_count']
  end

  def delete(sat)
    sat.systemCustominfo.deleteKey(@label)
  end

  def create(sat)
    sat.systemCustominfo.createKey(@label, @description)
  end
  
  def update(sat)
    sat.systemCustominfo.updateKey(@label, @description)
  end
end

class SystemCustominfosSet < OperationSet
  def delete(list)
    list.each do |custom_info|
      if custom_info.class == SystemCustominfos
        @sat.systemCustominfo.deleteKey(custom_info.label) 
      else
        @sat.systemCustominfo.deleteKey(custom_info['label']) 
      end
    end
  end

  def delete_all
    delete(@sat.systemCustominfo.listAllKeys)
  end

  def fetch_all
    system_infos=[]
    @sat.systemCustominfo.listAllKeys.each do |custom_info|
      system_infos << SystemCustominfo.new(custom_info)
    end
    system_infos
  end

  def include?(arg)
    include_label?(arg)
  end
end

class Systemgroup
  attr_reader :name

  def initialize(sysgroup)
    @id=sysgroup['id']
    @name=sysgroup['name']
    @description=sysgroup['description']
    @org_id=sysgroup['org_id']
    @system_count=sysgroup['system_count']
  end

  def create(sat)
    sat.systemgroup.create(@name, @description)
  end

  def update(sat)
    sat.systemgroup.update(@name, @description)
  end
end

class SystemgroupsSet < OperationSet
  def delete(list)
    list.each do |sysgroup|
      # To Fix - Stuct vs object issue
      if sysgroup.class == Systemgroup
        @sat.systemgroup.delete(sysgroup.name) 
      else
        @sat.systemgroup.delete(sysgroup['name']) 
      end
    end
  end

  def delete_all
    delete(@sat.systemgroup.listAllGroups)
  end

  def fetch_all
    sysgroups=[]
    @sat.systemgroup.listAllGroups.each do |sysgroup|
      sysgroups << Systemgroup.new(sysgroup)
    end
    sysgroups
  end

  def include?(arg)
    self.include_name?(arg)
  end
end

class User
  attr_reader :login

  def self.reader(sat, login)
    user={'login'=>login}
    user.merge!(sat.user.getDetails(login))
    user.merge!({'roles'=>sat.user.listRoles(login)})
    user.merge!({'assigned_system_groups'=>sat.user.listAssignedSystemGroups(login)})
    user.merge!({'default_system_groups'=>sat.user.listDefaultSystemGroups(login)})
    user
  end

  def initialize(user)
    @login=user['login']
    @first_name=user['first_name']
    @last_name=user['last_name']
    @email=user['email']
    @org_id=user['org_id']
    @prefix=user['prefix']
    @last_login_date=user['last_login_date']
    @created_date=user['created_date']
    @enabled=user['enabled']
    @use_pam=user['use_pam']
    @roles=user['roles']
    @assigned_system_groups=user['assigned_system_groups']
    @default_system_groups=user['default_system_groups']
  end


  def common_update(sat)
    # Enable/Disable
    if @enabled
      sat.user.enable(@login)
    else
      sat.user.disable(@login)
    end 
    
    # Adding roles
    @roles.each do |role|
      sat.user.addRole(@login, role)
    end

    # Assigned System Groups
    sat.user.addAssignedSystemGroups(@login, Helpers.filter(@assigned_system_groups, 'name'), false) unless @assigned_system_groups.empty?

    # Default System Groups
    sat.user.addDefaultSystemGroups(@login, Helpers.filter(@default_system_groups, 'name')) unless @default_system_groups.empty?
  end

  def create(sat)
   @use_pam
    if @use_pam
      sat.user.create(@login, "", @first_name, @last_name, @email, 1)
    else
      # When creating user on target, the passwor comes from configuration
      # because there no API to read it. 
      password=Users.password
      sat.user.create(@login, password, @first_name, @last_name, @email, 0)
    end
    common_update(sat)
  end

  def update(sat)
    @prefix='' unless @prefix
    # We ignore password update - Ain't any API for it!
    sat.user.setDetails(@login, {'first_name' => @first_name, 'last_name' => @last_name, 'email' => @email, 'prefix' => @prefix})
    sat.user.listRoles(login).each do |role|
      sat.user.removeRole(login, role)
    end
    common_update(sat)
  end
end

class UsersSet < OperationSet
  def delete(list)
    Users.exclude.each do |exclude|
      list.delete_if { |u| u == exclude }
    end
    list.each do |user|
      @sat.user.delete(user)
    end
  end

  def delete_all
    delete(Helpers.filter(@sat.user.listUsers, 'login'))
  end

  def disable(list)
    list.each do |user| 
      # Remove Roles first
      @sat.user.listRoles(user.login).each do |role|
        @sat.user.removeRole(user.login, role)
      end 
      # Disable User
      @sat.user.disable(user.login)
    end
  end

  def extra(list)
    # Users are not deleted by default but deactivated (to keep history)
    # unless delete option is true
    if Users.delete 
      delete(list)
    else
      disable(list)
    end
  end

  def fetch_all
    user_list=[]
    user_list=@sat.user.listUsers

    # users excluded from list option 
    Users.exclude.each do |exclude|
      user_list.delete_if { |u| u['login'] == exclude }
    end

    # Exclude deactivated users unless option activated
    unless Users.deactivated
      user_list.delete_if { |u| u['enabled'] == false }
    end
    
    users=[]
    Helpers.filter(user_list, 'login').each do |login|
      users << User.new(User.reader(@sat, login))
    end
    users
  end

  def include?(arg)
    self.include_login?(arg)
  end
end

# Satellite Interfacer 
class SatOperator
  attr_reader :source, :target, :operations
  
  # Operations are ordered - It matters for object dependencies
  OPS = [Systemgroups,
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
  @@syntax = <<eof 
Usage:
#{File.basename($0)} SAT CONFIG [OPTIONS] COMMAND

where:
SAT
  -s SAT-FILE, --satconfig=SAT-FILE

   SAT-FILE
     YAML formated file providing Satellite details:
     Use 'show sat' command to generate template
      
CONFIG
  -c CONFIG-FILE, --config=CONFIG-FILE

   CONFIG-FILE
     YAML formated file providing configuration options:
     Use 'show config' command to generate template
 
COMMAND
  destroy | export FORMAT <path> | extras | import FORMAT <path> | run <file> | sync | show SHOW_OPTION

  Commands explanation
    destroy: Delete all objects on target RHN Satellite
    
    export: Export RHN Satellite objects to files (ascci or binary formats) into <path> directory

    extras: Remove objects on target RHN Satellite not present in source RHN Satellite

    import: Import RHN Satellite object from files (ascii or binary) located into <path> directory
  
    run: Execute Ruby 'plug-in' file 

    sync: Synchronise object from source RHN Satellite to target RHN Satellite

    show: Generate configuration file examples

FORMAT
  ascii | bin
    - Ascii: YAML
    - Bin: Marshalling

SHOW_OPTION
  sat | config

[OPTIONS] 
  --ssl
   Activate SSL (HTTPS) sessions

  -d, --debug
   Activate debug output
 
  -h, --help
   This help

  -l, --log
   Append logs to file. By default logs go to Standard Output

  -w, --warnings
   Activate Ruby Verbose 

Examples
  # Synchronisation operation with logs to standard output
  ./satops.rb -s satellites -c config sync

  # Export operation in ASCII format with logs to file
  ./satops.rb -s satellites -c config -l export.log export ascii /tmp/satops-export/

  # Import operation from ASCII format with logs to file
  ./satops.rb -s satellites -c config -l import.log import ascii /tmp/satops-export/

  # Destroy operation with logs to standard output
  ./satops.rb -s satellites -c config destroy

Notes
    - Source RHN Satellite is never modified 
    - Target RHN Satellite is most likely to be modified
    - Operations are executed on object groups only if present (or uncommented) in configuration file 
eof

@@config_syntax = <<eof
# SatOps configuration file example 
#
# This is a YAML formatted file
# Respect indentations using spaces not tabulations
# Boolean values can be either yes/no or true/false
#
# Receivers - left part of assignment are keywords: Do not change them!
#
# First level correspond to Red Hat Network Satellite objects: e.g Activation Keys, Kickstart Profile, etc.
# This must be present (by default it's not!) to have operations to handle this group of RHN objects
#   Following levels with indentation are options
#   'update' is a common option to allow target object to be updated
#   Default values are always false, '' (empty) or nil
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
  password: ""
eof

 @@satellites_syntax = <<eof
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
eof

  def self.usage 
    puts @@syntax
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

    while !params.empty?
      case params[0]
      when '-c', '--config=' 
        params.shift
        @config_file=params[0]
      when '-d', '--debug'
        $DEBUG=true
      when '-h', '--help'
        Launcher.usage
      when '--ssl'
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
      when 'export'
        operation_size?(params, 3)
        @command='export'
        params.shift
        @format=params[0].to_sym
        params.shift
        @path=params[0]
      when 'extras'
        operation_size?(params, 1)
        @command='extra'
      when 'import'
        operation_size?(params, 3)
        @command='import'
        params.shift
        @format=params[0].to_sym
        params.shift
        @path=params[0]
      when 'sync'
        operation_size?(params, 1)
        @command='sync'
      when 'run'
        operation_size?(params, 2)
        @command='run'
        params.shift
        @file_to_run=params[0]
      when 'show'
        params.shift
        case params[0] 
        when 'sat'
          puts @@satellites_syntax
        when 'config'
          puts @@config_syntax
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

# Main
Launcher.new(ARGV)
