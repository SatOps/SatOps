module RHN
  # Represent the RHN Satellite XML-RPC server
  module Session
    @@path="/rpc/api"

    def self.running?(host, ssl)
      server=XMLRPC::Client.new(host, @@path, nil, nil, nil, nil, nil, ssl, 30)
      server.call('api.getVersion')
    rescue Errno::ECONNREFUSED => e
      puts "FATAL: #{host}: #{e}"
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
      @sat.log.info("#{@sat.host.login}@#{@sat.host.name}:#{str}")
    end

    def trace_warn(*params)
      str=""
      params.each { |p| str << "#{p}:" }
      @sat.log.warn("#{@sat.host.login}@#{@sat.host.name}:#{str}")
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

  class Org < Operation
    def initialize(sat)
      super(sat)
      define 'org.create'
      define 'org.delete', :boolean
      define 'org.getDetails'
      define 'org.listOrgs', :list
      define 'org.listSoftwareEntitlements', :list
      define 'org.listSoftwareEntitlementsForOrg', :list
      define 'org.listSystemEntitlements', :list
      define 'org.listSystemEntitlementsForOrg', :list
      define 'org.listUsers', :list
      define 'org.migrateSystems'
      define 'org.setSoftwareEntitlements', :boolean
      define 'org.setSoftwareFlexEntitlements', :boolean
      define 'org.setSystemEntitlements', :boolean
      define 'org.updateName'
    end
  end

  class OrgTrusts < Operation
    def initialize(sat)
      super(sat)
      define 'org.trusts.addTrust', :boolean
      define 'org.trusts.getDetails', :list
      define 'org.trusts.listChannelsConsumed', :list
      define 'org.trusts.listChannelsProvided', :list
      define 'org.trusts.listOrgs', :list
      define 'org.trusts.listSystemsAffected', :list
      define 'org.trusts.listTrusts', :list
      define 'org.trusts.removeTrust', :boolean
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
    attr_reader :host, :log, :activationkey, :channel, :channelSoftware, :configchannel, :kickstart, :kickstartFilepreservation, :kickstartProfile, :kickstartProfileSystem, :kickstartProfileSoftware, :kickstartKeys, :kickstartSnippet, :org, :orgTrusts, :system, :systemConfig, :systemCustominfo, :systemgroup, :user

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
      @org=Org.new(self)
      @orgTrusts=OrgTrusts.new(self)
      @system=System.new(self)
      @systemConfig=SystemConfig.new(self)
      @systemCustominfo=SystemCustominfo.new(self)
      @systemgroup=Systemgroup.new(self)
      @user=User.new(self)
    end
  end
end
