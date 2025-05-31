document.addEventListener('DOMContentLoaded', () => {
  const searchInput = document.getElementById('search');
  if (!searchInput) return;
  
  // Get all sections and sidebar links
  const sections = document.querySelectorAll('.section');
  const sidebarLinks = document.querySelectorAll('.sidebar-nav a');
  
  // Create index of all sections
  const searchIndex = [];
  
  sections.forEach(section => {
    const id = section.id;
    const title = section.querySelector('h2, h3')?.textContent || '';
    const content = section.textContent.toLowerCase();
    
    if (id && title) {
      searchIndex.push({
        id,
        title,
        content,
        element: section
      });
    }
  });
  
  // Search functionality
  searchInput.addEventListener('input', () => {
    const query = searchInput.value.trim().toLowerCase();
    
    if (!query) {
      // Show all sections when query is empty
      sections.forEach(section => {
        section.style.display = '';
      });
      return;
    }
    
    // Hide all sections first
    sections.forEach(section => {
      section.style.display = 'none';
    });
    
    // Find and show matching sections
    const results = searchIndex.filter(item => {
      return (
        item.title.toLowerCase().includes(query) ||
        item.content.includes(query)
      );
    });
    
    // Show matching sections
    results.forEach(result => {
      result.element.style.display = '';
    });
    
    // Find and expand the correct sidebar section for the first result
    if (results.length > 0) {
      const firstResultId = results[0].id;
      let sectionToExpand;
      
      if (firstResultId.startsWith('MySQL_')) {
        sectionToExpand = 'mysql';
      } else if (firstResultId.startsWith('MSSQL_')) {
        sectionToExpand = 'mssql';
      } else if (firstResultId.startsWith('Oracle_')) {
        sectionToExpand = 'oracle';
      } else if (firstResultId.startsWith('Extra_')) {
        sectionToExpand = 'extras';
      }
      
      if (sectionToExpand) {
        document.querySelectorAll('.sidebar-section').forEach(section => {
          section.classList.remove('active');
        });
        
        const sectionElement = document.querySelector(`.sidebar-section[data-section="${sectionToExpand}"]`);
        if (sectionElement) {
          sectionElement.classList.add('active');
        }
      }
    }
  });
});