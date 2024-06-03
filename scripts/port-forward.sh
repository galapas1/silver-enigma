# ssh -i ops.pem ec2-user@ec2-3-143-210-2.us-east-2.compute.amazonaws.com

ssh -i ops.pem -L 9092:ec2-3-143-210-2.us-east-2.compute.amazonaws.com:9092 ec2-user@ec2-3-143-210-2.us-east-2.compute.amazonaws.com
