REGION="ap-south-1"

EC2_RUNNING=$(aws ec2 describe-instances --region $REGION --filters "Name=instance-state-name,Values=running" --query "Reservations[*].Instances[*].InstanceId" --output text)

if [ -n "$EC2_RUNNING" ]; then
    aws ec2 stop-instances --region $REGION --instance-ids $EC2_RUNNING
fi

RDS_AVAILABLE=$(aws rds describe-db-instances --region $REGION --query "DBInstances[?DBInstanceStatus=='available'].DBInstanceIdentifier" --output text)

for db in $RDS_AVAILABLE; do
    aws rds stop-db-instance --region $REGION --db-instance-identifier $db
done