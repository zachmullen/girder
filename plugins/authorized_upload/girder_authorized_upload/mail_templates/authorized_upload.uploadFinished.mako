<%include file="_header.mako"/>

<p>
An upload you authorized has been completed. The resulting file is
<a href="${host}#file/${fileId}">here</a>.
</p>

<p>
<div><b>Name:</b> ${fileName}</div>
<div><b>Description:</b> ${fileDescription}</div>
</p>

<%include file="_footer.mako"/>
