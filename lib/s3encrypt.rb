require 'aws-sdk'
require 'openssl'
require 'thor'

module S3Encrypt
  require "s3encrypt/version"

  class CLI < Thor
    class_option  :credential_file, 
                  :aliases => :c, 
                  :desc => "AWS credential file",
                  :default => '~/.s3encrypt'
    class_option  :access_key, 
                  :aliases => :a, 
                  :desc => "AWS access key"
    class_option  :secret_key, 
                  :aliases => :s, 
                  :desc => "AWS secret key"
    class_option  :encryption_file, 
                  :aliases => :e, 
                  :desc => "Encryption file name",
                  :default => '~/.s3encrypt'
    class_option  :bucket, 
                  :aliases => :b, 
                  :desc => "S3 Bucket to upload file to",
                  :default => 's3encrypt'

    desc "create-key", "Creates key files for encryption"
    def create_key
      if File.exists?(private_key)
        puts "Please remove #{private_key} before recreating it!"
      else
        gen_key
     end
    end

    desc "list-buckets", "Lists all of your buckets"
    def list_buckets
      s3.buckets.each do |bucket|
        puts bucket.name
      end
    end

    desc "create-bucket name", "Create an s3 bucket"
    method_option :region, :default => "US"
    def create_bucket(name)
      s3.buckets.create(name)
    end

    desc "delete-bucket name", "Delete an s3 bucket and all its contents"
    def delete_bucket(name)
      bucket = s3.buckets[name]
      bucket.delete!
    end

    desc "list-objects bucket", "List all the keys in a specific bucket"
    def list_objects(bucket)
      bucket = s3.buckets[bucket]
      bucket.objects.each do |obj|
        puts obj.key
      end
    end

    desc "put bucket object", "Put the object in the bucket"
    def put(bucket, object)
      bucket = s3.buckets[bucket]
      bucket.objects[object].write(File.open(object), :encryption_key => crypt)
    end

    desc "remove bucket object", "IN DEVELOPMENT... Remove the object in the bucket"
    def remove
      puts "In development"
    end

    desc "get bucket object", "Get the object in the bucket"
    def get(bucket, object)
      bucket = s3.buckets[bucket]
      open object, 'w' do |io| io.write bucket.objects[object].read(:encryption_key => crypt) end
    end

    private
    def credentials
      @credentials ||= read_credentials
    end

    def private_key
      @private_key ||= File.expand_path(options[:encryption_file] + '.pri.pem') 
    end

    def public_key
      @public_key ||= File.expand_path(options[:encryption_file] + '.pub.pem')
    end

    def crypt
      if File.exists?(private_key)
        @crypt ||= OpenSSL::PKey::RSA.new File.read(private_key)
      else
        @crypt ||= gen_key
      end
    end

    def gen_key
      encryption_key = OpenSSL::PKey::RSA.new(4096)
      puts "Writing #{private_key}"
      puts "Writing #{public_key}"
      File.open(private_key, 'w') { |io| io.write encryption_key.to_pem }
      File.open(public_key, 'w') { |io| io.write encryption_key.public_key.to_pem } 
    end 

    def read_credentials
      access_key = secret_key = nil

      if options[:access_key] || options[:secret_key]
        access_key = options[:access_key]
        secret_key = options[:secret_key]
      else
        File.open(File.expand_path(options[:credential_file])).each do |line|
          access_key = $1 if line =~ /^AWSAccessKeyId=(.*)$/
          secret_key = $1 if line =~ /^AWSSecretKey=(.*)$/
        end
      end
      return [access_key, secret_key]
    end

    def s3
      access_key, secret_key = credentials
      @s3 ||= AWS::S3.new(:access_key_id => access_key, :secret_access_key => secret_key)
    end

  end
end
