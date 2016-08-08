

module ConfigHelper
  ######################################################################################
  ###########################  AWS Config Setup ########################################
  ######################################################################################

  def ConfigHelper.awsConfigSetup(configFile, op)

    aws_config_file = File.expand_path(configFile)

    unless File.exist?(aws_config_file)
      config_file_not_exist aws_config_file
      puts op
      exit 1
    end

    aws_config = YAML.load(File.read(aws_config_file))

    unless aws_config.kind_of?(Hash) && aws_config.keys.include?('access_key_id') && aws_config.keys.include?('secret_access_key')
      aws_config_malformed
      puts op
      exit 1
    end

    aws_config

  end

  ######################################################################################
  ###########################  Environment Config Setup ################################
  ######################################################################################

  def ConfigHelper.env_config_setup(configFile, op = nil)
    env_config_file = File.expand_path(configFile)

    unless File.exist?(env_config_file)
      config_file_not_exist env_config_file
      puts op
      exit 1
    end

    env_config = YAML.load(File.read(env_config_file))

    unless (env_config.kind_of?(Hash) && validate_env_config(env_config))
      envConfigFileMalformed
      puts op
      exit 1
    end

    env_config
  end

  ######################################################################################
  ###########################  Module Helper Functions #################################
  ######################################################################################


  def ConfigHelper.validate_env_config(env_config_hash={})
    true
  end

  def ConfigHelper.config_file_not_exist(configfile)
    puts <<-END
------------------------------------------------------------
The specified file : #{configfile},
    does not exist, please correct the path
------------------------------------------------------------
  END

  end

  def ConfigHelper.aws_config_malformed
    puts <<-END
--------------------------------------------------------------------------
aws_config.yml is formatted incorrectly.  Please use the following format:

access_key_id: YOUR_ACCESS_KEY_ID
secret_access_key: YOUR_SECRET_ACCESS_KEY
--------------------------------------------------------------------------
  END

  end
end
