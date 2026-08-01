REGION="ap-south-1"

EC2_STOPPED=$(aws ec2 describe-instances --region $REGION --filters "Name=instance-state-name,Values=stopped" --query "Reservations[*].Instances[*].InstanceId" --output text)

if [ -n "$EC2_STOPPED" ]; then
    aws ec2 start-instances --region $REGION --instance-ids $EC2_STOPPED
fi

RDS_STOPPED=$(aws rds describe-db-instances --region $REGION --query "DBInstances[?DBInstanceStatus=='stopped'].DBInstanceIdentifier" --output text)

for db in $RDS_STOPPED; do
    aws rds start-db-instance --region $REGION --db-instance-identifier $db
done