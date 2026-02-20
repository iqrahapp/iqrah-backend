-- Add device metadata columns for better observability

ALTER TABLE devices ADD COLUMN IF NOT EXISTS os TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS app_version TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_model TEXT;

-- Create index for filtering devices by OS
CREATE INDEX IF NOT EXISTS idx_devices_os ON devices(os);
