resource "google_compute_network" "control" {
  project                 = var.project_id
  name                    = "${local.prefix}-control"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  depends_on = [google_project_service.required["compute.googleapis.com"]]
}

resource "google_compute_subnetwork" "control" {
  project                  = var.project_id
  name                     = "${local.prefix}-control"
  region                   = var.region
  network                  = google_compute_network.control.id
  ip_cidr_range            = "10.42.0.0/24"
  private_ip_google_access = true
}

resource "google_vpc_access_connector" "serverless" {
  project       = var.project_id
  name          = "${local.prefix}-vpc"
  region        = var.region
  network       = google_compute_network.control.name
  ip_cidr_range = "10.42.1.0/28"
  min_instances = 2
  max_instances = 3

  depends_on = [google_project_service.required["vpcaccess.googleapis.com"]]
}

# The optional SDK provider has its own connector so its fail-closed egress
# policy cannot interfere with the production-safe control-plane services.
resource "google_vpc_access_connector" "antigravity" {
  count = var.antigravity_demo_enabled ? 1 : 0

  project       = var.project_id
  name          = "${local.prefix}-ag"
  region        = var.region
  network       = google_compute_network.control.name
  ip_cidr_range = "10.42.2.0/28"
  min_instances = 2
  max_instances = 3

  depends_on = [google_project_service.required["vpcaccess.googleapis.com"]]
}

resource "google_dns_managed_zone" "restricted_googleapis" {
  count = var.antigravity_demo_enabled ? 1 : 0

  project     = var.project_id
  name        = "${local.prefix}-restricted-googleapis"
  dns_name    = "googleapis.com."
  description = "Routes the isolated SDK provider only through restricted Google APIs."
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.control.id
    }
  }

  depends_on = [google_project_service.required["dns.googleapis.com"]]
}

resource "google_dns_record_set" "restricted_googleapis_a" {
  count = var.antigravity_demo_enabled ? 1 : 0

  project      = var.project_id
  managed_zone = google_dns_managed_zone.restricted_googleapis[0].name
  name         = "restricted.googleapis.com."
  type         = "A"
  ttl          = 300
  rrdatas      = ["199.36.153.4", "199.36.153.5", "199.36.153.6", "199.36.153.7"]
}

resource "google_dns_record_set" "restricted_googleapis_cname" {
  count = var.antigravity_demo_enabled ? 1 : 0

  project      = var.project_id
  managed_zone = google_dns_managed_zone.restricted_googleapis[0].name
  name         = "*.googleapis.com."
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["restricted.googleapis.com."]
}

resource "google_compute_firewall" "antigravity_allow_restricted_googleapis" {
  count = var.antigravity_demo_enabled ? 1 : 0

  project     = var.project_id
  name        = "${local.prefix}-ag-googleapis"
  network     = google_compute_network.control.name
  direction   = "EGRESS"
  priority    = 900
  target_tags = ["vpc-connector-${var.region}-${local.prefix}-ag"]

  destination_ranges = ["199.36.153.4/30"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "antigravity_deny_other_egress" {
  count = var.antigravity_demo_enabled ? 1 : 0

  project            = var.project_id
  name               = "${local.prefix}-ag-deny-egress"
  network            = google_compute_network.control.name
  direction          = "EGRESS"
  priority           = 1000
  target_tags        = ["vpc-connector-${var.region}-${local.prefix}-ag"]
  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }
}

resource "google_compute_global_address" "private_services" {
  project       = var.project_id
  name          = "${local.prefix}-private-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.control.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.control.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]

  depends_on = [google_project_service.required["servicenetworking.googleapis.com"]]
}
