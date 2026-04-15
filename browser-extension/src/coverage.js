// Site access and native connectivity do not establish general upload coverage.
export function siteCoverage(origin) {
 const hostname=new URL(origin).hostname;
 if(hostname==='mail.google.com')return {supported:true,mode:'gmail-drop-guard',label:'Enable Gmail file-drop guard',message:'Conservative Gmail guard: blocks ALL file drag-and-drop. Selective inspection, paperclip attachments, Google Drive attachments and email sending are not protected.'};
 return {supported:true,mode:'multipart',label:'Enable form gate on this site',message:'Limited coverage: standard HTML POST multipart upload forms only. Custom AJAX uploads, drag-and-drop and email sending are not protected.'};
}
