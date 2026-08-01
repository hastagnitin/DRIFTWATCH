EC2_STOPPED=$(aws ec2 describe-instances --filters "Name=instance-state-name,Values=stopped" --query "Reservations[*].Instances[*].InstanceId" --output text)

if [ -n "$EC2_STOPPED" ]; then
    aws ec2 start-instances --instance-ids $EC2_STOPPED
fi

RDS_STOPPED=$(aws rds describe-db-instances --query "DBInstances[?DBInstanceStatus=='stopped'].DBInstanceIdentifier" --output text)

for db in $RDS_STOPPED; do
    aws rds start-db-instance --db-instance-identifier $db
done