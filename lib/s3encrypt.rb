require 'aws-sdk'
require 'openssl'
require 'thor'
require 'securerandom'

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
    class_option  :pub, 
                  :aliases => :p, 
                  :desc => "Public key file"
#                  :default => '~/.s3encrypt.pub'
    class_option  :priv, 
                  :aliases => :k, 
                  :desc => "Private key file"
#                  :default => '~/.s3encrypt.pem'
    class_option  :bucket, 
                  :aliases => :b, 
                  :desc => "S3 Bucket to upload file to",
                  :default => 's3encrypt'
    class_option  :unencrypted, 
                  :type => :boolean,
                  :aliases => :u, 
                  :desc => "Do not decrypt file"
    class_option  :rotate, 
                  :aliases => :r,
                  :desc => "Key to rotate to"
    class_option  :metadata, 
                  :aliases => :m,
                  :desc => "User defined metadata for key identification",
                  :default => 'encryption_key'

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
    def list_objects(name)
      bucket = s3.buckets[name]
      bucket.objects.each do |obj|
        puts obj.key unless obj.key =~ /^.*\.instruction$/
      end
    end

    desc "put bucket object", "Put the object in the bucket"
    def put(name, object)
      puts "Using #{File.basename(public_key)} for encryption"
      bucket = s3.buckets[name]
      bucket.objects[object].write(File.open(object), 
                                   :encryption_key => pubcrypt, 
                                   :encryption_materials_location => :instruction_file)
      bucket.objects[object].metadata[options[:metadata]] = File.basename(public_key)
    end

    desc "remove bucket object", "Remove the object in the bucket"
    def remove(name, object)
      bucket = s3.buckets[name]
      bucket.objects[object].delete
      bucket.objects[object + '.instruction'].delete
    end

    desc "get bucket object", "Get the object in the bucket"
    def get(name, object)
      puts "Using #{File.basename(private_key)} for decryption"
      bucket = s3.buckets[name]
      if options[:unencrypted]
        open object, 'w' do |io| 
          io.write bucket.objects[object].read 
        end
      else
        open object, 'w' do |io| 
          io.write bucket.objects[object].read(:encryption_key => crypt, 
                                               :encryption_materials_location => :instruction_file) 
        end
      end
    end

    desc "inspect bucket object", "Return the metadata for an object"
    def inspect(name, object)
      bucket = s3.buckets[name]
      puts "#{bucket.objects[object].metadata[options[:metadata]]}"
    end

    desc "rotate bucket object", "Re-encrypt file using new key"
    def rotate(name, object)
      tmpfile = SecureRandom.urlsafe_base64(20)
      bucket = s3.buckets[name]
      open tmpfile, 'w' do |io| 
        io.write bucket.objects[object].read(:encryption_key => crypt, 
                                             :encryption_materials_location => :instruction_file) 
      end
      bucket.objects[object].write(File.open(tmpfile), 
                                   :encryption_key => rotate_crypt, 
                                   :encryption_materials_location => :instruction_file)
      bucket.objects[object].metadata[options[:metadata]] = File.basename(rotate_key)
      File.delete(tmpfile)
    end

    desc "rotateall bucket", "Re-encrypt all files using the new key"
    def rotateall(name)
      bucket = s3.buckets[name]
      bucket.objects.each do |obj|
        next if obj.key =~ /^.*\.instruction$/
        if obj.metadata[options[:metadata]] == File.basename(rotate_key) 
          puts "#{obj.key} is already rotated"
        else
          print "#{obj.key} ...  "
          rotate(name, obj.key.to_s)
          puts "rotated"
        end
      end
    end

    private
    def credentials
      @credentials ||= read_credentials
    end

    def private_key
      if options[:priv]
        @private_key ||= File.expand_path(options[:priv])
      else
        puts "ERROR: Key not supplied"
        exit
      end
    end

    def public_key
      if options[:pub]
        @public_key ||= File.expand_path(options[:pub])
      else
        puts "ERROR: Public key not supplied"
        exit
      end
    end

    def rotate_key
      if options[:rotate]
        @rotate_key ||= File.expand_path(options[:rotate])
      else
        puts "ERROR: Rotate key not supplied"
        exit
      end
    end

    def crypt
      if File.exists?(private_key)
        @crypt ||= OpenSSL::PKey::RSA.new File.read(private_key)
      else
        puts "ERROR: Unable to retrieve private key"
        exit
      end
    end

    def rotate_crypt
      if File.exists?(rotate_key)
         @rotate_crypt ||= OpenSSL::PKey::RSA.new File.read(rotate_key)
      else
        puts "ERROR: Unable to retrieve rotate key"
        exit
      end
    end

    def pubcrypt
      if File.exists?(public_key)
        @pubcrypt ||= OpenSSL::PKey::RSA.new File.read(public_key)
      else
        puts "ERROR: Unable to retrieve public key"
        exit
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
