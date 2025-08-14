import streamlit as st
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from PIL import Image
import io
import os
import re
import urllib.parse as urlparse
import json
import csv
import pandas as pd
from datetime import datetime

# Google Drive API setup
SCOPES = [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/drive.readonly'
]
CLIENT_SECRETS_FILE = "clientSecretKey.json"
CSV_FILENAME = "Annotated_output.csv"

# Image quality assessment options
QUALITY_ISSUES = [
    "Image is blurry, lesions are hard to see.",
    "Oral cavity or lesion is out of focus.",
    "Image is cropped too tightly, oral cavity unclear.",
    " Too much face visible; oral cavity not well shown.",
    "Image taken from a wrong angle.",
    "Lesion is hidden due to poor retraction.",
    "Shadow obscures the lesion or oral cavity.",
    "Retractor blocks view of the lesion.",
    "Debris or saliva obscures the lesion.",
    "Other factors degrade image quality."
]

def get_google_drive_service():
    """Get or create Google Drive service with improved authentication flow"""
    # Check if we already have a valid service
    if 'drive_service' in st.session_state:
        return st.session_state.drive_service
    
    # Check if we have stored credentials
    creds = None
    if 'drive_creds' in st.session_state:
        try:
            creds = Credentials.from_authorized_user_info(st.session_state.drive_creds)
            if creds and creds.valid:
                service = build('drive', 'v3', credentials=creds)
                st.session_state.drive_service = service
                return service
        except Exception as e:
            st.error(f"Error with stored credentials: {str(e)}")
            # Clear invalid credentials
            if 'drive_creds' in st.session_state:
                del st.session_state['drive_creds']
    
    return None

def authenticate_google_drive():
    """Improved Google Drive authentication with better debugging"""
    st.write("Initializing authentication...")  # This should appear immediately
    
    if not os.path.exists(CLIENT_SECRETS_FILE):
        st.error("Missing clientSecretKey.json file")
        return False

    try:
        # Create flow with local server for OAuth
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri="http://localhost:8501"  # Keep using localhost
        )
        
        # Generate authorization URL
        auth_url, _ = flow.authorization_url(
            prompt="consent",
            access_type="offline",
            include_granted_scopes="true"
        )
        
        # Display auth instructions
        st.markdown("## Google Drive Authorization")
        st.markdown(f"1. [Click here to authorize]({auth_url})")
        st.markdown("2. After approving, you'll be redirected to a blank page")
        st.markdown("3. Copy the ENTIRE URL from that page and paste below:")
        
        # Get the redirect URL from user
        with st.form("auth_url_form"):
            redirect_url = st.text_input("Paste redirect URL here:")
            submitted = st.form_submit_button("Complete Authorization")
            
            if submitted and redirect_url:
                st.write("Processing authorization...")  # Debug point
                
                # Extract code from URL - FIXED THIS PART
                try:
                    parsed = urlparse.urlparse(redirect_url)
                    query_params = urlparse.parse_qs(parsed.query)
                    code = query_params.get('code', [None])[0]
                    
                    if not code:
                        st.error("No authorization code found in URL")
                        return False
                    
                    # Exchange code for tokens
                    flow.fetch_token(code=code)
                    creds = flow.credentials
                    
                    # Store credentials
                    st.session_state.drive_creds = {
                        'token': creds.token,
                        'refresh_token': creds.refresh_token,
                        'token_uri': creds.token_uri,
                        'client_id': creds.client_id,
                        'client_secret': creds.client_secret,
                        'scopes': creds.scopes
                    }
                    
                    # Build service
                    service = build('drive', 'v3', credentials=creds)
                    st.session_state.drive_service = service
                    
                    st.success("Authentication successful!")
                    st.balloons()
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Authorization failed: {str(e)}")
                    return False

    except Exception as e:
        st.error(f"Authentication setup failed: {str(e)}")
        return False
    
    return False

def extract_folder_id(url):
    """Extract folder ID from various Google Drive URL formats"""
    if not url:
        return None
        
    # Clean the URL
    url = url.strip()
    
    # Different patterns for folder ID extraction
    patterns = [
        r'/folders/([a-zA-Z0-9_-]+)',
        r'id=([a-zA-Z0-9_-]+)',
        r'folders/([a-zA-Z0-9_-]+)',
        r'^([a-zA-Z0-9_-]{28,})$'  # Direct folder ID
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            folder_id = match.group(1)
            # Validate folder ID length (Google Drive folder IDs are typically 28+ characters)
            if len(folder_id) >= 28:
                return folder_id
    
    # If no pattern matches, assume it's a direct folder ID
    if len(url) >= 28 and re.match(r'^[a-zA-Z0-9_-]+$', url):
        return url
    
    return None

def get_existing_csv_data(service, folder_id):
    """Get existing CSV data from Google Drive folder and return as list of dicts"""
    try:
        # Search for existing CSV file in the folder
        query = f"'{folder_id}' in parents and name='{CSV_FILENAME}' and trashed=false"
        results = service.files().list(q=query, fields="files(id, name)").execute()
        files = results.get('files', [])
        
        if files:
            # Download and read the existing CSV
            csv_file = files[0]
            request = service.files().get_media(fileId=csv_file['id'])
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request)
            
            done = False
            while not done:
                _, done = downloader.next_chunk()
            
            fh.seek(0)
            # Read CSV into list of dictionaries
            df = pd.read_csv(fh)
            return df.to_dict('records')
        
        return []
    except Exception as e:
        st.warning(f"Could not read existing CSV: {str(e)}")
        return []

def fetch_images_from_drive(service, folder_id, page_token=None):
    """Fetch images from Google Drive folder with pagination support"""
    if not service or not folder_id:
        st.error("Missing service or folder ID")
        return [], None  # Return both files and next_page_token
    
    try:
        # Query for image files in the folder
        image_mimetypes = [
            'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 
            'image/webp', 'image/bmp', 'image/tiff'
        ]
        
        mimetype_query = " or ".join([f"mimeType='{mt}'" for mt in image_mimetypes])
        query = f"'{folder_id}' in parents and ({mimetype_query}) and trashed=false"
        
        results = service.files().list(
            q=query,
            fields="files(id, name, mimeType, size), nextPageToken",
            pageSize=1000,  # Get up to 1000 images per batch
            orderBy="name",
            pageToken=page_token
        ).execute()
        
        files = results.get('files', [])
        next_page_token = results.get('nextPageToken')
        
        # Get existing CSV data to filter out already assessed images
        existing_filenames = get_existing_csv_data(service, folder_id)
        if existing_filenames:
            st.info(f"Found {len(existing_filenames)} already assessed images that will be skipped")
        
        # Filter out already assessed images
        unassessed_files = [f for f in files if f['name'] not in existing_filenames]
        
        if not files:
            st.warning("No images found in this folder")
            return [], None
            
        if not unassessed_files:
            st.warning("All images in this batch have been assessed!")
            return [], next_page_token
            
        st.info(f"Found {len(unassessed_files)} unassessed image(s) in this batch")
        return unassessed_files, next_page_token
        
    except Exception as e:
        st.error(f"Drive API error: {str(e)}")
        return [], None
        
def download_image(service, file_info):
    """Download a single image from Google Drive"""
    try:
        # Download file
        request = service.files().get_media(fileId=file_info['id'])
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        
        done = False
        while not done:
            _, done = downloader.next_chunk()
        
        # Process image
        fh.seek(0)
        img = Image.open(fh)
        
        # Convert to RGB if necessary (for JPEG compatibility)
        if img.mode in ('RGBA', 'LA', 'P'):
            img = img.convert('RGB')
        
        return img
        
    except Exception as e:
        st.error(f"Couldn't download {file_info['name']}: {str(e)}")
        return None

def upload_csv_to_drive(service, folder_id, csv_data):
    """Upload or update CSV file in Google Drive folder with improved error handling"""
    try:
        if not csv_data or not isinstance(csv_data, list):
            st.warning("No valid CSV data to upload")
            return False
        
        # Define the CSV headers in the correct order
        headers = [
            'filename', 'accept', 'Blur', 'Out of focus', 'Overcropped', 
            'Undercropped', 'Improper Angle', 'Oral Cavity not retracted well',
            'Shadow Covering oral Cavity', 'Retractor Covering the lesion A',
            'Lots of Debris/Saliva', 'Others', 'timestamp'
        ]
        
        # Convert data to CSV format
        csv_buffer = io.StringIO()
        csv_writer = csv.DictWriter(csv_buffer, fieldnames=headers)
        
        # Write headers
        csv_writer.writeheader()
        
        # Write data rows - ensure each row is a dictionary
        for row_data in csv_data:
            if not isinstance(row_data, dict):
                st.warning(f"Skipping invalid row data: {row_data}")
                continue
            csv_writer.writerow(row_data)
        
        csv_content = csv_buffer.getvalue()
        
        if len(csv_content) == 0:
            st.error("CSV content is empty!")
            return False
        
        # Check if CSV already exists
        query = f"'{folder_id}' in parents and name='{CSV_FILENAME}' and trashed=false"
        results = service.files().list(q=query, fields="files(id, name)").execute()
        files = results.get('files', [])
        
        # Reset buffer position before reading
        csv_buffer.seek(0)
        csv_bytes = io.BytesIO(csv_buffer.getvalue().encode('utf-8'))
        media = MediaIoBaseUpload(csv_bytes, mimetype='text/csv', resumable=True)
        
        if files:
            # Update existing file
            file_id = files[0]['id']
            try:
                updated_file = service.files().update(
                    fileId=file_id,
                    media_body=media,
                    fields='id,name'
                ).execute()
                st.success(f"CSV file updated successfully: {updated_file.get('name')}")
                return True
            except Exception as update_error:
                st.error(f"Failed to update CSV file: {str(update_error)}")
                return False
        else:
            # Create new file
            file_metadata = {
                'name': CSV_FILENAME,
                'parents': [folder_id],
                'mimeType': 'text/csv'
            }
            try:
                created_file = service.files().create(
                    body=file_metadata,
                    media_body=media,
                    fields='id,name,parents'
                ).execute()
                st.success(f"CSV file created successfully: {created_file.get('name')}")
                return True
            except Exception as create_error:
                st.error(f"Failed to create CSV file: {str(create_error)}")
                return False
        
    except Exception as e:
        st.error(f"Failed to upload CSV to Google Drive: {str(e)}")
        return False

def save_assessment_data(image_assessments):
    """Save assessment data to session state and optionally export"""
    st.session_state.image_assessments = image_assessments
    
    # Create exportable data
    export_data = []
    for image_id, assessment in image_assessments.items():
        # Find image name from files
        image_name = "Unknown"
        for file_info in st.session_state.image_files:
            if file_info['id'] == image_id:
                image_name = file_info['name']
                break
        
        export_data.append({
            'image_id': image_id,
            'image_name': image_name,
            'status': assessment.get('status', 'Unknown'),
            'quality_issues': assessment.get('quality_issues', []),
            'timestamp': assessment.get('timestamp', '')
        })
    
    return export_data

def initialize_session_state():
    """Initialize session state variables"""
    if 'current_image_index' not in st.session_state:
        st.session_state.current_image_index = 0
    if 'image_files' not in st.session_state:
        st.session_state.image_files = []
    if 'current_image' not in st.session_state:
        st.session_state.current_image = None
    if 'image_assessments' not in st.session_state:
        st.session_state.image_assessments = {}
    if 'csv_data' not in st.session_state:
        st.session_state.csv_data = []
    if 'next_page_token' not in st.session_state:
        st.session_state.next_page_token = None
    if 'total_batches' not in st.session_state:
        st.session_state.total_batches = 1
    if 'current_batch' not in st.session_state:
        st.session_state.current_batch = 1
    if 'loaded_existing_data' not in st.session_state:
        st.session_state.loaded_existing_data = False


def render_quality_checkboxes(current_file, current_assessment):
    """Render quality issues as checkboxes with improved styling"""
    st.markdown("**Select any quality issues present in this image (only required for Reject):**")
    
    # Initialize the checkbox states for this image
    checkbox_key_prefix = f"quality_checkbox_{current_file['id']}"
    
    # Get previously selected issues
    previously_selected = current_assessment.get('quality_issues', [])
    
    selected_issues = []
    
    # Create checkboxes for each quality issue
    for i, issue in enumerate(QUALITY_ISSUES):
        checkbox_key = f"{checkbox_key_prefix}_{i}"
        
        # Check if this issue was previously selected
        is_checked = issue in previously_selected
        
        # Create the checkbox
        if st.checkbox(
            issue,
            value=is_checked,
            key=checkbox_key,
            help=f"Quality issue {i+1}: {issue[:50]}..." if len(issue) > 50 else f"Quality issue {i+1}"
        ):
            selected_issues.append(issue)
    
    return selected_issues

def update_csv_assessment(file_info, status, quality_issues):
    """Update CSV data with assessment - returns properly formatted dictionary"""
    # Map quality issues to column names
    issue_columns = {
        "Image is blurry, lesions are hard to see.": "Blur",
        "Oral cavity or lesion is out of focus.": "Out of focus",
        "Image is cropped too tightly, oral cavity unclear.": "Overcropped",
        " Too much face visible; oral cavity not well shown.": "Undercropped",
        "Image taken from a wrong angle.": "Improper Angle",
        "Lesion is hidden due to poor retraction.": "Oral Cavity not retracted well",
        "Shadow obscures the lesion or oral cavity.": "Shadow Covering oral Cavity",
        "Retractor blocks view of the lesion.": "Retractor Covering the lesion A",
        "Debris or saliva obscures the lesion.": "Lots of Debris/Saliva",
        "Other factors degrade image quality.": "Others"
    }
    
    # Prepare the data row with all required columns
    row = {
        'filename': file_info['name'],
        'accept': 'Yes' if status == 'Accepted' else 'No',
        'Blur': 'No',
        'Out of focus': 'No',
        'Overcropped': 'No',
        'Undercropped': 'No',
        'Improper Angle': 'No',
        'Oral Cavity not retracted well': 'No',
        'Shadow Covering oral Cavity': 'No',
        'Retractor Covering the lesion A': 'No',
        'Lots of Debris/Saliva': 'No',
        'Others': 'No',
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Mark 'Yes' for any quality issues if rejected
    if status == 'Rejected':
        for issue in quality_issues:
            if issue in issue_columns:
                row[issue_columns[issue]] = 'Yes'
    
    return row

def process_assessment(service, file_info, status, quality_issues):
    """Process assessment and handle CSV operations with better error handling"""
    try:
        # Update CSV data - get properly formatted dictionary
        csv_row = update_csv_assessment(file_info, status, quality_issues)
        
        # Ensure we're working with a list of dictionaries
        if not isinstance(st.session_state.csv_data, list):
            st.session_state.csv_data = []
        
        # Add to session state CSV data
        st.session_state.csv_data.append(csv_row)
        
        # Try to upload CSV to Google Drive
        if hasattr(st.session_state, 'current_folder_id'):
            try:
                # First try to upload the full CSV
                upload_success = upload_csv_to_drive(
                    service, 
                    st.session_state.current_folder_id, 
                    st.session_state.csv_data  # This should be a list of dicts
                )
                
                if not upload_success:
                    # If full upload fails, try just uploading the new row
                    st.warning("Full CSV upload failed, trying single row upload...")
                    upload_success = upload_csv_to_drive(
                        service, 
                        st.session_state.current_folder_id, 
                        [csv_row]  # Single row as a list with one dict
                    )
                
                if upload_success:
                    st.success(f"Image {status.lower()} and CSV updated successfully!")
                else:
                    st.warning(f"Image {status.lower()} but CSV upload failed. Data saved locally.")
                    # Save to local file as backup
                    try:
                        with open('local_backup.csv', 'a', newline='') as f:
                            writer = csv.DictWriter(f, fieldnames=csv_row.keys())
                            if f.tell() == 0:  # Write header if file is empty
                                writer.writeheader()
                            writer.writerow(csv_row)
                    except Exception as local_error:
                        st.error(f"Failed to save local backup: {str(local_error)}")
            except Exception as e:
                st.warning(f"Image {status.lower()} but CSV upload failed: {str(e)}")
                st.info("Assessment data is still saved in the current session.")
        else:
            st.warning("No folder ID found for CSV upload. Data saved in session only.")
        
        return True
        
    except Exception as e:
        st.error(f"Error processing assessment: {str(e)}")
        return False

def check_drive_permissions(service, folder_id):
    """Check if we have write permissions on the folder"""
    try:
        folder = service.files().get(
            fileId=folder_id,
            fields='permissions'
        ).execute()
        
        permissions = folder.get('permissions', [])
        for perm in permissions:
            if perm.get('role') in ['owner', 'writer']:
                return True
        return False
    except Exception as e:
        st.error(f"Error checking permissions: {str(e)}")
        return False

def verify_folder_write_access(service, folder_id):
    """Verify we can write to the folder"""
    if not check_drive_permissions(service, folder_id):
        st.error("You don't have write permissions on this folder!")
        st.info("Please make sure:")
        st.info("1. You're the owner of the folder, OR")
        st.info("2. You have 'Editor' access to the folder")
        return False
    return True

def main():
    st.title("OraiBio Image Classification Tool")
    
    # Initialize session state
    initialize_session_state()
    
    # Sidebar for controls
    with st.sidebar:
        st.header("Controls")
        
        # Authentication status
        service = get_google_drive_service()
        if service:
            st.success("Authenticated")
            if st.button("Reset Authentication"):
                # Clear all authentication data
                keys_to_remove = ['drive_creds', 'drive_service', 'image_files', 
                                'current_image', 'current_image_index', 
                                'image_assessments', 'csv_data', 'next_page_token',
                                'total_batches', 'current_batch', 'current_folder_id']
                for key in keys_to_remove:
                    if key in st.session_state:
                        del st.session_state[key]
                st.rerun()
        else:
            st.info("Not authenticated")
        
        # Assessment summary in sidebar
        if st.session_state.image_files and st.session_state.image_assessments:
            st.markdown("---")
            st.subheader("Assessment Progress")
            total_images = len(st.session_state.image_files)
            assessed_images = len(st.session_state.image_assessments)
            
            # Count accepted and rejected images
            accepted_count = sum(1 for assessment in st.session_state.image_assessments.values() 
                               if assessment.get('status') == 'Accepted')
            rejected_count = sum(1 for assessment in st.session_state.image_assessments.values() 
                               if assessment.get('status') == 'Rejected')
            
            # Batch information
            st.metric("Current Batch", f"{st.session_state.current_batch}/{st.session_state.total_batches}")
            st.metric("Images in Batch", f"{assessed_images}/{total_images}")
            st.metric("Accepted", accepted_count)
            st.metric("Rejected", rejected_count)
            
            if assessed_images > 0:
                progress_percent = (assessed_images / total_images) * 100
                st.progress(progress_percent / 100)
                
                # Export button
                if st.button("Export Assessment Data"):
                    export_data = save_assessment_data(st.session_state.image_assessments)
                    json_data = json.dumps(export_data, indent=2)
                    st.download_button(
                        label="Download JSON",
                        data=json_data,
                        file_name="image_quality_assessment.json",
                        mime="application/json"
                    )
    
    # Main content
    service = get_google_drive_service()
    
    if not service:
        # Show authentication interface
        authenticate_google_drive()
    else:
        # Show main functionality once authenticated
        st.success("Connected to Google Drive")
        
        st.markdown("---")
        st.subheader("Fetch Images from Google Drive")
        
        folder_url = st.text_input(
            "Google Drive Folder URL or ID:",
            placeholder="https://drive.google.com/drive/folders/1ABCDefGhIjKlMnOpQrStUvWxYz or just the folder ID",
            help="You can paste either the full folder URL or just the folder ID"
        )
        
        if folder_url and st.button("Fetch Images", type="primary"):
            folder_id = extract_folder_id(folder_url)
            if not folder_id:
                st.error("Invalid folder URL or ID. Please check your input.")
                st.info("Make sure you're using a valid Google Drive folder link or folder ID.")
            else:
                # Verify write access before proceeding
                if verify_folder_write_access(service, folder_id):
                    with st.spinner("Loading images from Google Drive..."):
                        # Initialize batch tracking
                        st.session_state.next_page_token = None
                        st.session_state.current_batch = 1
                        st.session_state.total_batches = 1
                        st.session_state.current_folder_id = folder_id
                        
                        # Load existing CSV data if not already loaded
                        if not st.session_state.loaded_existing_data:
                            existing_data = get_existing_csv_data(service, folder_id)
                            if existing_data:
                                st.session_state.csv_data = existing_data
                                # Populate image_assessments from existing data
                                for row in existing_data:
                                    filename = row['filename']
                                    status = 'Accepted' if row['accept'] == 'Yes' else 'Rejected'
                                    quality_issues = []
                                    # Map quality issues back from columns
                                    issue_mapping = {
                                        'Blur': "Image is blurry, lesions are hard to see.",
                                        'Out of focus': "Oral cavity or lesion is out of focus.",
                                        'Overcropped': "Image is cropped too tightly, oral cavity unclear.",
                                        'Undercropped': " Too much face visible; oral cavity not well shown.",
                                        'Improper Angle': "Image taken from a wrong angle.",
                                        'Oral Cavity not retracted well': "Lesion is hidden due to poor retraction.",
                                        'Shadow Covering oral Cavity': "Shadow obscures the lesion or oral cavity.",
                                        'Retractor Covering the lesion A': "Retractor blocks view of the lesion.",
                                        'Lots of Debris/Saliva': "Debris or saliva obscures the lesion.",
                                        'Others': "Other factors degrade image quality."
                                    }
                                    for col, issue in issue_mapping.items():
                                        if row.get(col) == 'Yes':
                                            quality_issues.append(issue)
                                    
                                    # Find the file ID for this filename
                                    file_id = None
                                    for file_info in st.session_state.image_files:
                                        if file_info['name'] == filename:
                                            file_id = file_info['id']
                                            break
                                    
                                    if file_id:
                                        st.session_state.image_assessments[file_id] = {
                                            'status': status,
                                            'quality_issues': quality_issues,
                                            'timestamp': row.get('timestamp', '')
                                        }
                            st.session_state.loaded_existing_data = True
                        
                        # Fetch first batch
                        image_files, next_page_token = fetch_images_from_drive(
                            service, 
                            folder_id,
                            st.session_state.next_page_token
                        )
                        
                        if image_files:
                            st.session_state.image_files = image_files
                            st.session_state.current_image_index = 0
                            st.session_state.current_image = None
                            st.session_state.next_page_token = next_page_token
                            
                            # Update total batches estimate if there are more
                            if next_page_token:
                                st.session_state.total_batches += 1
                            
                            st.rerun()
                        else:
                            st.warning("No unassessed images found in this folder")
    # Display image navigation and assessment
    if st.session_state.image_files:
        st.markdown("---")
        
        current_idx = st.session_state.current_image_index
        total_images = len(st.session_state.image_files)
        current_file = st.session_state.image_files[current_idx]
        
        # Header with image info
        st.subheader(f"Image {current_idx + 1} of {total_images} (Batch {st.session_state.current_batch})")
        st.write(f"**{current_file['name']}**")
        
        # Load current image if not already loaded
        if (st.session_state.current_image is None or 
            getattr(st.session_state, 'loaded_image_index', -1) != current_idx):
            
            with st.spinner("Loading image..."):
                image = download_image(service, current_file)
                if image:
                    st.session_state.current_image = image
                    st.session_state.loaded_image_index = current_idx
        
        # Display current image and quality assessment
        if st.session_state.current_image:
            col1, col2 = st.columns([1, 1])
            
            with col1:
                st.image(st.session_state.current_image, use_container_width=True)
            
            with col2:
                st.markdown("### Image Quality Assessment")
                current_assessment = st.session_state.image_assessments.get(current_file['id'], {})
                selected_issues = render_quality_checkboxes(current_file, current_assessment)
            
            # Action buttons
            st.markdown("---")
            col1, col2, col3 = st.columns([1, 1, 1])
            
            with col1:
                if st.button("Accept", type="primary", key=f"accept_{current_file['id']}", use_container_width=True):
                    assessment_data = {
                        'status': 'Accepted',
                        'quality_issues': [],
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    st.session_state.image_assessments[current_file['id']] = assessment_data
                    
                    if process_assessment(service, current_file, 'Accepted', []):
                        if current_idx < total_images - 1:
                            st.session_state.current_image_index = current_idx + 1
                            st.session_state.current_image = None
                            st.rerun()
                        else:
                            handle_batch_completion(service)
            
            with col3:
                reject_disabled = len(selected_issues) == 0
                if st.button("Reject", disabled=reject_disabled, key=f"reject_{current_file['id']}", 
                           help="Select at least one quality issue to reject", use_container_width=True):
                    assessment_data = {
                        'status': 'Rejected',
                        'quality_issues': selected_issues,
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    st.session_state.image_assessments[current_file['id']] = assessment_data
                    
                    if process_assessment(service, current_file, 'Rejected', selected_issues):
                        if current_idx < total_images - 1:
                            st.session_state.current_image_index = current_idx + 1
                            st.session_state.current_image = None
                            st.rerun()
                        else:
                            handle_batch_completion(service)
            
            # Navigation buttons
            st.markdown("---")
            col1, col2 = st.columns([1, 1])
            
            with col1:
                if st.button("Previous", disabled=(current_idx == 0), use_container_width=True):
                    st.session_state.current_image_index = max(0, current_idx - 1)
                    st.session_state.current_image = None
                    st.rerun()
            
            with col2:
                if st.button("Next", disabled=(current_idx == total_images - 1), use_container_width=True):
                    st.session_state.current_image_index = min(total_images - 1, current_idx + 1)
                    st.session_state.current_image = None
                    st.rerun()
            
            # Progress bar
            progress = (current_idx + 1) / total_images
            st.progress(progress, text=f"Image {current_idx + 1} of {total_images}")
            
        else:
            st.error("Failed to load current image")
    
    # Batch navigation controls
    if (st.session_state.image_files and 'next_page_token' in st.session_state and 
        st.session_state.current_image_index == len(st.session_state.image_files) - 1):
        
        st.markdown("---")
        if st.session_state.next_page_token:
            if st.button("Load Next Batch (1000 images)", type="primary"):
                load_next_batch(service)
        else:
            st.success("All batches completed! All images have been assessed.")

def handle_batch_completion(service):
    """Handle actions when a batch is completed"""
    if 'next_page_token' in st.session_state and st.session_state.next_page_token:
        st.info("You've completed this batch. Click 'Load Next Batch' to continue.")
    else:
        st.success("All images in all batches have been assessed!")
    st.rerun()

def load_next_batch(service):
    """Load the next batch of images"""
    with st.spinner("Loading next batch of images..."):
        image_files, next_page_token = fetch_images_from_drive(
            service,
            st.session_state.current_folder_id,
            st.session_state.next_page_token
        )
        
        if image_files:
            st.session_state.image_files = image_files
            st.session_state.current_image_index = 0
            st.session_state.current_image = None
            st.session_state.image_assessments = {}
            st.session_state.next_page_token = next_page_token
            st.session_state.current_batch += 1
            
            # Update total batches if we found more pages
            if next_page_token and st.session_state.current_batch >= st.session_state.total_batches:
                st.session_state.total_batches += 1
            
            st.rerun()
        else:
            st.warning("No unassessed images found in next batch")
            if next_page_token:
                st.session_state.next_page_token = next_page_token
                st.rerun()

if __name__ == "__main__":
    main()
